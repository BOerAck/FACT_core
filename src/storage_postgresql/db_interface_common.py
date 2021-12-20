import logging
from contextlib import contextmanager
from typing import Dict, List, Optional, Set, Union

from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm.exc import NoResultFound

from objects.file import FileObject
from objects.firmware import Firmware
from storage_postgresql.entry_conversion import file_object_from_entry, firmware_from_entry
from storage_postgresql.query_conversion import build_query_from_dict
from storage_postgresql.schema import AnalysisEntry, Base, FileObjectEntry, FirmwareEntry, fw_files_table
from storage_postgresql.tags import append_unique_tag

PLUGINS_WITH_TAG_PROPAGATION = [  # FIXME This should be inferred in a sensible way. This is not possible yet.
    'crypto_material', 'cve_lookup', 'known_vulnerabilities', 'qemu_exec', 'software_components',
    'users_and_passwords'
]

Summary = Dict[str, List[str]]


class DbInterfaceError(Exception):
    pass


class DbInterface:
    def __init__(self, database='fact_db'):
        self.engine = create_engine(f'postgresql:///{database}')
        self.base = Base
        self.base.metadata.create_all(self.engine)
        self._session_maker = sessionmaker(bind=self.engine, future=True)  # future=True => sqlalchemy 2.0 support

    @contextmanager
    def get_read_only_session(self) -> Session:
        session: Session = self._session_maker()
        session.connection(execution_options={'postgresql_readonly': True, 'postgresql_deferrable': True})
        try:
            yield session
        finally:
            session.close()

    def exists(self, uid: str) -> bool:
        with self.get_read_only_session() as session:
            query = select(FileObjectEntry.uid).filter(FileObjectEntry.uid == uid)
            return bool(session.execute(query).scalar())

    def is_firmware(self, uid: str) -> bool:
        with self.get_read_only_session() as session:
            query = select(FirmwareEntry.uid).filter(FirmwareEntry.uid == uid)
            return bool(session.execute(query).scalar())

    def is_file_object(self, uid: str) -> bool:
        # aka "is_not_firmware"
        return not self.is_firmware(uid) and self.exists(uid)

    def all_uids_found_in_database(self, uid_list: List[str]) -> bool:
        if not uid_list:
            return True
        with self.get_read_only_session() as session:
            query = select(func.count(FileObjectEntry.uid)).filter(FileObjectEntry.uid.in_(uid_list))
            return session.execute(query).scalar() >= len(uid_list)

    # ===== Read / SELECT =====

    def get_object(self, uid: str) -> Optional[Union[FileObject, Firmware]]:
        if self.is_firmware(uid):
            return self.get_firmware(uid)
        return self.get_file_object(uid)

    def get_firmware(self, uid: str) -> Optional[Firmware]:
        with self.get_read_only_session() as session:
            try:
                fw_entry = self._get_firmware_entry(uid, session)
                return self._firmware_from_entry(fw_entry)
            except NoResultFound:
                return None

    def _firmware_from_entry(self, fw_entry: FirmwareEntry, analysis_filter: Optional[List[str]] = None) -> Firmware:
        firmware = firmware_from_entry(fw_entry, analysis_filter)
        firmware.analysis_tags = self._collect_analysis_tags_from_children(firmware.uid)
        return firmware

    @staticmethod
    def _get_firmware_entry(uid: str, session: Session) -> FirmwareEntry:
        query = select(FirmwareEntry).filter_by(uid=uid)
        return session.execute(query).scalars().one()

    def get_file_object(self, uid: str) -> Optional[FileObject]:
        with self.get_read_only_session() as session:
            fo_entry = session.get(FileObjectEntry, uid)
            if fo_entry is None:
                return None
            return file_object_from_entry(fo_entry)

    def get_objects_by_uid_list(self, uid_list: List[str], analysis_filter: Optional[List[str]] = None) -> List[FileObject]:
        with self.get_read_only_session() as session:
            query = select(FileObjectEntry).filter(FileObjectEntry.uid.in_(uid_list))
            return [
                self._firmware_from_entry(fo_entry.firmware, analysis_filter) if fo_entry.is_firmware
                else file_object_from_entry(fo_entry, analysis_filter)
                for fo_entry in session.execute(query).scalars()
            ]

    def get_analysis(self, uid: str, plugin: str) -> Optional[AnalysisEntry]:
        with self.get_read_only_session() as session:
            try:
                query = select(AnalysisEntry).filter_by(uid=uid, plugin=plugin)
                return session.execute(query).scalars().one()
            except NoResultFound:
                return None

    # ===== included files. =====

    def get_list_of_all_included_files(self, fo: FileObject) -> Set[str]:
        if isinstance(fo, Firmware):
            return self.get_all_files_in_fw(fo.uid)
        return self.get_all_files_in_fo(fo)

    def get_uids_of_all_included_files(self, uid: str) -> Set[str]:
        return self.get_all_files_in_fw(uid)  # FixMe: rename call

    def get_all_files_in_fw(self, fw_uid: str) -> Set[str]:
        '''Get a set of UIDs of all files (recursively) contained in a firmware'''
        with self.get_read_only_session() as session:
            query = select(fw_files_table.c.file_uid).where(fw_files_table.c.root_uid == fw_uid)
            return set(session.execute(query).scalars())

    def get_all_files_in_fo(self, fo: FileObject) -> Set[str]:
        '''Get a set of UIDs of all files (recursively) contained in a file'''
        with self.get_read_only_session() as session:
            return self._get_files_in_files(session, fo.files_included).union({fo.uid, *fo.files_included})

    def _get_files_in_files(self, session, uid_set: Set[str], recursive: bool = True) -> Set[str]:
        if not uid_set:
            return set()
        query = select(FileObjectEntry).filter(FileObjectEntry.uid.in_(uid_set))
        included_files = {
            child.uid
            for fo in session.execute(query).scalars()
            for child in fo.included_files
        }
        if recursive and included_files:
            included_files.update(self._get_files_in_files(session, included_files))
        return included_files

    # ===== summary =====

    def get_complete_object_including_all_summaries(self, uid: str) -> FileObject:
        '''
        input uid
        output:
            like get_object, but includes all summaries and list of all included files set
        '''
        fo = self.get_object(uid)
        if fo is None:
            raise Exception(f'UID not found: {uid}')
        fo.list_of_all_included_files = self.get_list_of_all_included_files(fo)
        for plugin, analysis_result in fo.processed_analysis.items():
            analysis_result['summary'] = self.get_summary(fo, plugin)
        return fo

    def get_summary(self, fo: FileObject, selected_analysis: str) -> Optional[Summary]:
        if selected_analysis not in fo.processed_analysis:
            logging.warning(f'Analysis {selected_analysis} not available on {fo.uid}')
            return None
        if 'summary' not in fo.processed_analysis[selected_analysis]:
            return None
        if not isinstance(fo, Firmware):
            return self._collect_summary(fo.list_of_all_included_files, selected_analysis)
        return self._collect_summary_from_included_objects(fo, selected_analysis)

    def _collect_summary_from_included_objects(self, fw: Firmware, plugin: str) -> Summary:
        included_files = self.get_all_files_in_fw(fw.uid).union({fw.uid})
        with self.get_read_only_session() as session:
            query = select(AnalysisEntry.uid, AnalysisEntry.summary).filter(
                AnalysisEntry.plugin == plugin,
                AnalysisEntry.uid.in_(included_files)
            )
            summary = {}
            for uid, summary_list in session.execute(query):  # type: str, List[str]
                for item in summary_list or []:
                    summary.setdefault(item, []).append(uid)
        return summary

    def _collect_summary(self, uid_list: List[str], selected_analysis: str) -> Summary:
        summary = {}
        file_objects = self.get_objects_by_uid_list(uid_list, analysis_filter=[selected_analysis])
        for fo in file_objects:
            self._update_summary(summary, self._get_summary_of_one(fo, selected_analysis))
        return summary

    @staticmethod
    def _update_summary(original_dict: Summary, update_dict: Summary):
        for item in update_dict:
            original_dict.setdefault(item, []).extend(update_dict[item])

    @staticmethod
    def _get_summary_of_one(file_object: Optional[FileObject], selected_analysis: str) -> Summary:
        summary = {}
        if file_object is None:
            return summary
        try:
            for item in file_object.processed_analysis[selected_analysis].get('summary') or []:
                summary[item] = [file_object.uid]
        except KeyError as err:
            logging.warning(f'Could not get summary: {err}', exc_info=True)
        return summary

    # ===== tags =====

    def _collect_analysis_tags_from_children(self, uid: str) -> dict:
        unique_tags = {}
        with self.get_read_only_session() as session:
            query = (
                select(FileObjectEntry.uid, AnalysisEntry.plugin, AnalysisEntry.tags)
                .filter(FileObjectEntry.root_firmware.any(uid=uid))
                .join(AnalysisEntry, FileObjectEntry.uid == AnalysisEntry.uid)
                .filter(AnalysisEntry.tags != JSONB.NULL, AnalysisEntry.plugin.in_(PLUGINS_WITH_TAG_PROPAGATION))
            )
            for _, plugin, tags in session.execute(query):
                for tag_type, tag in tags.items():
                    if tag_type != 'root_uid' and tag['propagate']:
                        append_unique_tag(unique_tags, tag, plugin, tag_type)
        return unique_tags

    # ===== misc. =====

    def get_specific_fields_of_fo_entry(self, uid: str, fields: List[str]) -> tuple:
        with self.get_read_only_session() as session:
            field_attributes = [getattr(FileObjectEntry, field) for field in fields]
            query = select(*field_attributes).filter_by(uid=uid)  # ToDo FixMe?
            return session.execute(query).one()

    def get_firmware_number(self, query: Optional[dict] = None) -> int:
        with self.get_read_only_session() as session:
            db_query = select(func.count(FirmwareEntry.uid))
            if query:
                db_query = db_query.filter_by(**query)  # FixMe: no generic query supported?
            return session.execute(db_query).scalar()

    def get_file_object_number(self, query: dict, zero_on_empty_query: bool = True) -> int:
        if zero_on_empty_query and query == {}:
            return 0
        with self.get_read_only_session() as session:
            query = build_query_from_dict(query, query=select(func.count(FileObjectEntry.uid)))
            return session.execute(query).scalar()

    def set_unpacking_lock(self, uid):
        # self.locks.insert_one({'uid': uid})
        pass  # ToDo FixMe?

    def check_unpacking_lock(self, uid):
        # return self.locks.count_documents({'uid': uid}) > 0
        pass  # ToDo FixMe?

    def release_unpacking_lock(self, uid):
        # self.locks.delete_one({'uid': uid})
        pass  # ToDo FixMe?

    def drop_unpacking_locks(self):
        # self.main.drop_collection('locks')
        pass  # ToDo FixMe?


class ReadWriteDbInterface(DbInterface):

    @contextmanager
    def get_read_write_session(self) -> Session:
        session = self._session_maker()
        try:
            yield session
            session.commit()
        except (SQLAlchemyError, DbInterfaceError) as err:
            logging.error(f'Database error when trying to write to the Database: {err}', exc_info=True)
            session.rollback()
            raise
        finally:
            session.close()