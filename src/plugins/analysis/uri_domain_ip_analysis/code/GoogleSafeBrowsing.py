from ipaddress import ip_address
from dns import resolver
import whois
import pprint
import requests
from pysafebrowsing import SafeBrowsing
import time, pprint, datetime
from ipwhois.net import Net
from ipwhois.asn import IPASN


from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	NAME = 'GoogleSafeBrowsing_Analysis'
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
		key="AIzaSyAICqqWIkZfocwxVmP0FIGrBkNcMoVZg-0"
		self.gsb = SafeBrowsing(key)
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
					final_data['GoogleSafeBrowsingURI'] = {}
					final_data['GoogleSafeBrowsingURI'][data] = self.GSB_check(data)
				
					data = self.get_domains_from_uri(data)
					final_data['GoogleSafeBrowsingDomain'] = {}
					final_data['GoogleSafeBrowsingDomain'][data] = self.GSB_check(data)
					domains_to_ips = self.get_ips_from_domain(data)
					for ip in domains_to_ips:
						final_data['GoogleSafeBrowsingDomain'][f'{data} to_ip: {ip}'] = self.GSB_check(ip)

				elif key == 'ips_v4':
					final_data['GoogleSafeBrowsingIP'] = {}
					final_data['GoogleSafeBrowsingIP'][data] = self.GSB_check(data)
					ips_to_domains = self.get_domains_from_ip(data)
					for domain in ips_to_domains:
						final_data['GoogleSafeBrowsingIP'][f'{data} to_domain: {domain}'] = self.GSB_check(domain)
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
	
		
		
	def GSB_check(self, value):
		# lookup_urls(['http://malware.testing.google.test/testing/malware/'])
		try:
			response = self.gsb.lookup_urls([value])
			return pprint.pformat(response)
		except Exception as e:
			return {'ERROR': e}
	
	@staticmethod
	def _remove_duplicates(input_list):
		return list(set(input_list))
	
	def get_summary(self):
		return {'domains_from_uris':self.domains_from_uris,'ips_from_domains':self.ips_from_domains,'domains_from_ips':self.domains_from_ips}





