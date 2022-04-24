from ipaddress import ip_address
from dns import resolver
import whois
import requests
import io
import pandas as pd
from zipfile import ZipFile
import time, pprint, datetime
from ipwhois.net import Net
from ipwhois.asn import IPASN

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	NAME = 'URLHaus_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	DESCRIPTION = (
	'Returns the results of DNS and WHOIS queries for identified IPS and URIs'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		self.domains_from_uris = 0
		self.ips_from_domains = 0
		self.domains_from_ips = 0
		self.ip_and_uri_finder = CommonAnalysisIPAndURIFinder()
		super().__init__(plugin_administrator, config=config, recursive=recursive, timeout=timeout, plugin_path=__file__)

	def process_object(self, file_object):
		final_data = {} #dict of original artifact mapped to analysis
		result = self.ip_and_uri_finder.analyze_file(file_object.file_path, separate_ipv6=True)
		for key in ['uris', 'ips_v4', 'ips_v6']:
		    result[key] = self._remove_duplicates(result[key])
		self.init_urlhaus()
		for key, data_list in result.items():
			if key not in ['uris', 'ips_v4', 'ips_v6']:
				continue
			for data in data_list:
				print(f'$ {data} - {type(data)}')
				if type(data) == list:
					print(f'##DATA LIST: {data}')
					data = data[0]
				if key == 'uris':
					final_data['URLHausURI'] = {}
					final_data['URLHausURI'][data] = self.URLHaus_check(data)
				
					data = self.get_domains_from_uri(data)
					final_data['URLHausDomain'] = {}
					final_data['URLHausDomain'][data] = self.URLHaus_check(data)
					domains_to_ips = self.get_ips_from_domain(data)
					for ip in domains_to_ips:
						final_data['URLHausDomain'][f'{data} to_ip: {ip}'] = self.URLHaus_check(ip)

				elif key == 'ips_v4':
					final_data['URLHausIP'] = {}
					final_data['URLHausIP'][data] = self.URLHaus_check(data)
					ips_to_domains = self.get_domains_from_ip(data)
					for domain in ips_to_domains:
						final_data['URLHausIP'][f'{data} to_domain: {domain}'] = self.URLHaus_check(domain)
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
	
	def init_urlhaus(self):
		url = "https://urlhaus.abuse.ch/downloads/csv/"
		response = requests.get(url)
		tempfile = io.BytesIO(response.content)
		input_zip=ZipFile(tempfile)
		d = {name: input_zip.read(name) for name in input_zip.namelist()}
		csv = d['csv.txt']
		tempfile = io.BytesIO(csv)
		tempfile.seek(0)
		pcsv = pd.read_csv(tempfile,on_bad_lines='skip',skiprows = [i for i in range(0, 8) ])
		self.urlhaus_csv = pcsv
		
		
	def URLHaus_check(self, value):
		return_dict = {'count':0,'last_match':{}}
		for index, row in self.urlhaus_csv.iterrows():
			url = row['url']
			if value in url:
				return_dict['count'] += 1
				return_dict['last_match'] = self.urlhaus_csv.loc[index].to_dict()
		return return_dict
	
	@staticmethod
	def _remove_duplicates(input_list):
		return list(set(input_list))
	
	def get_summary(self):
		return {'domains_from_uris':self.domains_from_uris,'ips_from_domains':self.ips_from_domains,'domains_from_ips':self.domains_from_ips}





