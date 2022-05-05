from ipaddress import ip_address
from dns import resolver
import whois
import pprint
import requests
from pysafebrowsing import SafeBrowsing
import time, pprint, datetime


from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	NAME = 'GoogleSafeBrowsing_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	DESCRIPTION = (
	'Returns the results of API queries to Google Safe Browsing for domain, IPs and URIs. API key required.'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		self.ip_and_uri_finder = CommonAnalysisIPAndURIFinder()
		key="AIzaSyAICqqWIkZfocwxVmP0FIGrBkNcMoVZg-0"
		self.gsb = SafeBrowsing(key)
		super().__init__(plugin_administrator, config=config, recursive=recursive, timeout=timeout, plugin_path=__file__)

	def process_object(self, file_object):
		final_data = {} #dict of original artifact mapped to analysis
		#result = self.ip_and_uri_finder.analyze_file(file_object.file_path, separate_ipv6=True)
		result = file_object.processed_analysis['ip_and_uri_finder']['summary']


		for data in result:
			if type(data) != str:
				continue
			final_data[data] = {}
			if not self.is_ip(data):
				final_data[data]['GoogleSafeBrowsingURI'] = self.GSB_check(data)
			
				data = self.get_domains_from_uri(data)
				final_data[data] = {}
				final_data[data]['GoogleSafeBrowsingDomain'] = self.GSB_check(data)
				domains_to_ips = self.get_ips_from_domain(data)
				for ip in domains_to_ips:
					final_data[data][f'GoogleSafeBrowsing extraced_data {data} to_ip: {ip}'] = self.GSB_check(ip)

			else:
				final_data[data]['GoogleSafeBrowsingIP'] = self.GSB_check(data)
				ips_to_domains = self.get_domains_from_ip(data)
				for domain in ips_to_domains:
					final_data[data][f'GoogleSafeBrowsing {data} to_domain: {domain}'] = self.GSB_check(domain)

		file_object.processed_analysis[self.NAME] = final_data
		return file_object
	
	def is_ip(self,data):
		try:
			ip_address(data)
			return True
		except:
			return False
		
		
	def GSB_check(self, value):
		# lookup_urls(['http://malware.testing.google.test/testing/malware/'])
		try:
			response = self.gsb.lookup_urls([value])
			return pprint.pformat(response)
		except Exception as e:
			return "No data found, or asset is not a web host"
			
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




