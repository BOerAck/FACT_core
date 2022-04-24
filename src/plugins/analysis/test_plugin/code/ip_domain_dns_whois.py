from ipaddress import ip_address
from dns import resolver
import whois
import time, pprint, datetime
from ipwhois.net import Net
from ipwhois.asn import IPASN

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	#NAME = 'IP_Domain_DNS_WHOIS'
	NAME = 'test_plugin'
	DEPENDENCIES = ['ip_and_uri_finder']
	DESCRIPTION = (
	'Returns the results of DNS and WHOIS queries for identified IPS and URIs'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		self.domains_from_uris = 0
		self.ips_from_domains = 0
		self.domains_from_ips = 0
		self.ip_whois = 0
		self.domain_whois = 0
		self.ip_and_uri_finder = CommonAnalysisIPAndURIFinder()
		super().__init__(plugin_administrator, config=config, recursive=recursive, timeout=timeout, plugin_path=__file__)

	def process_object(self, file_object):
		final_data = {} #dict of original artifact mapped to analysis
		result = self.ip_and_uri_finder.analyze_file(file_object.file_path, separate_ipv6=True)
		for key in ['uris', 'ips_v4', 'ips_v6']:
		    result[key] = self._remove_duplicates(result[key])
		for key, data_list in result.items():
			if key not in ['uris', 'ips_v4', 'ips_v6']:
				continue
			for data in data_list:
				print(f'$ {data} - {type(data)}')
				if type(data) == list:
					print(f'##DATA LIST: {data}')
					data = data[0]
				if key == 'uris':
					data = self.get_domains_from_uri(data)
					final_data[data] = {}
					final_data[data]['dns'] = self.get_ips_from_domain(data)
					final_data[data]['whois'] = self.get_domain_whois(data)
				elif key == 'ips_v4':
					final_data[data] = {}
					final_data[data]['dns'] = self.get_domains_from_ip(data)
					final_data[data]['whois'] = self.get_ip_whois(data)
		final_data['summary'] = self.get_summary()
		print(f'##################\n\n{final_data}\n\n################')
		file_object.processed_analysis[self.NAME] = final_data #self._get_augmented_result(result)
		return file_object
		
	def get_domains_from_uri(self, uri):
		sub_strs = uri.split("://")
		if len(sub_strs) == 1: #case where no protocol
			domain = (sub_strs[0])
		else:
			domain = (sub_strs[1].split("/")[0])
		self.domains_from_uris += 1
		return domain
		

	def get_ips_from_domain(self, domain):
		try:
			ips = []
			response = resolver.resolve(domain,'A')
			for ip in response:
				ips.append(str(ip))
			self.ips_from_domains += 1
			return ips
		except:
			return [f'Error resolving {domain}']
	def get_domains_from_ip(self, ip):
		try:
			domains = []
			print(f'requesting {ip}')
			response = resolver.resolve_address(ip)
			for domain in response:
				domains.append(str(domain))
			self.domains_from_ips += len(domains)
			return domains
		except Exception as e:
			return [f'No DNS records found {ip}']
			
	def get_ip_whois(self, ip):
		try:
			result = pprint.pformat(IPASN(Net(ip)).lookup())
			self.ip_whois += 1
			return result
		except Exception as e:
			return {f'Error retrieving WHOSI information for {ip}':f'ERROR: {e}'}
		
	def get_domain_whois(self, domain):
		try:
			data_dict = whois.query(domain)
			if not data_dict:
				return {'No WHOIS records found.':domain}
			else:
				data_dict = data_dict.__dict__
			for key, value in data_dict.items():
				if type(value) == set:
					data_dict[key] = list(data_dict[key])
				elif type(value) == datetime.datetime:
					data_dict[key] = value.strftime("%m-%d-%y %H:%M")
			if 'statuses' in data_dict:
				data_dict.pop('statuses')
			self.domain_whois += 1
			return pprint.pformat(data_dict)
		except Exception as e:
			return {'Error encountered while retrieving WHIOS information for {domain}':f'ERROR: {e}'}
		
	
	
	@staticmethod
	def _remove_duplicates(input_list):
		return list(set(input_list))
	
	def get_summary(self):
		return {'domains_from_uris':self.domains_from_uris,'ips_from_domains':self.ips_from_domains,'domains_from_ips':self.domains_from_ips,'ip_whois':self.ip_whois,'domain_whois':self.domain_whois}





