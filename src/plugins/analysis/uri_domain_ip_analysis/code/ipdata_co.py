from ipaddress import ip_address
from dns import resolver
import whois
import requests
import time, pprint, datetime
from ipwhois.net import Net
from ipwhois.asn import IPASN

from ipdata import ipdata




from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	NAME = 'ipdata_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	DESCRIPTION = (
	'Returns the results of DNS and WHOIS queries for identified IPS and URIs'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		self.domains_from_uris = 0
		self.ips_from_domains = 0
		self.domains_from_ips = 0
		key = '94e7d24a7610566ca951ae281d974d19d7be21764420af641f2f6d0a'
		self.ipd=ipdata.IPData(key)
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
					final_data['ipdataDomain_to_IP'] = {}
					domains_to_ips = self.get_ips_from_domain(data)
					for ip in domains_to_ips:
						final_data['ipdataDomain_to_IP'][f'{data} to_ip: {ip}'] = self.ipdata_location(ip)

				elif key == 'ips_v4':
					final_data['ipdataIP'] = {}
					final_data['ipdataIP'][data] = self.ipdata_location(data)
					
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
			
	def ipdata_location(self, ip):
		#locators = ['country_name', 'continent_name', 'latitude', 'longitude', 'company', 'threat','asn']
		#return_dict = {}
		try:
			response = self.ipd.lookup(ip)
			#for locator in locators:
				#return_dict[locator] = response[locator]
			return pprint.pformat(response)
		except Exception as e:
			return {'ERROR': e}

		#return pprint.pformat(return_dict)
	
	
	@staticmethod
	def _remove_duplicates(input_list):
		return list(set(input_list))
	
	def get_summary(self):
		return {'ips_from_domains':self.ips_from_domains}

'''
def ipdata_location(ip):
	key = '94e7d24a7610566ca951ae281d974d19d7be21764420af641f2f6d0a'
	idp = ipdata.IPData(key)
	locators = ['country_name', 'continent_name', 'latitude', 'longitude', 'company', 'threat','asn']
	return_dict = {}
	try:
		response = ipd.lookup(ip)
		for locator in locators:
			return_dict[locator] = response[locator]
	except Exception as e:
		return {'ERROR': e}
	finally:
		return pprint.pformat(return_dict)
'''





