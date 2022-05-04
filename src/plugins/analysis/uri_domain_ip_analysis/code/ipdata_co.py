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
	NAME = 'ipdata.co_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	DESCRIPTION = (
	'Returns the results of API queries to ipdata.co for IPs. API key required.'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		key = '94e7d24a7610566ca951ae281d974d19d7be21764420af641f2f6d0a'
		self.ipd=ipdata.IPData(key)
		self.ip_and_uri_finder = CommonAnalysisIPAndURIFinder()
		super().__init__(plugin_administrator, config=config, recursive=recursive, timeout=timeout, plugin_path=__file__)

	def process_object(self, file_object):
		final_data = {} #dict of original artifact mapped to analysis
		result = self.ip_and_uri_finder.analyze_file(file_object.file_path, separate_ipv6=True)
		for key in ['uris', 'ips_v4', 'ips_v6']:
		    result[key] = self.remove_duplicates(result[key])
		for key, data_list in result.items():
			if key not in ['uris', 'ips_v4', 'ips_v6']:
				continue
			for data in data_list:
				if key == 'uris':
					data = self.get_domains_from_uri(data)
					final_data[data] = {}
					domains_to_ips = self.get_ips_from_domain(data)
					for ip in domains_to_ips:
						final_data[data][f'IPdata.co {data} to_ip: {ip}'] = self.ipdata_location(ip)

				elif key == 'ips_v4':
					final_data[data] = {}
					final_data[data]['ipdataIP'] = self.ipdata_location(data)
					
		file_object.processed_analysis[self.NAME] = final_data
		return file_object
		
	def ipdata_location(self, ip):
		try:
			response = self.ipd.lookup(ip)
			return pprint.pformat(response)
		except Exception as e:
			return {'ERROR': ip}
		
	def get_domains_from_uri(self, uri):
		sub_strs = uri.split("://")
		if len(sub_strs) == 1: #case where no protocol
			domain = (sub_strs[0])
		else:
			domain = (sub_strs[1].split("/")[0])
		return domain
		

	def get_ips_from_domain(self, domain):
		try:
			ips = []
			response = resolver.resolve(domain,'A')
			for ip in response:
				ips.append(str(ip))
			return ips
		except:
			return [f'Error resolving {domain}']
	def get_domains_from_ip(self, ip):
		try:
			domains = []
			response = resolver.resolve_address(ip)
			for domain in response:
				domains.append(str(domain))
			return domains
		except Exception as e:
			return [f'No DNS records found {ip}']
			

	def remove_duplicates(self, input_list):
		return list(set(input_list))
	



