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
	NAME = 'DNS_WHOIS_domain_ip'
	DEPENDENCIES = ['ip_and_uri_finder']
	MIME_WHITELIST = ['text/plain', 'application/octet-stream', 'application/x-executable', 'application/x-object','application/x-sharedlib', 'application/x-dosexec']
	DESCRIPTION = (
	'Returns the results of DNS and WHOIS queries for identified IPS and Domains. No API key required.'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):

		self.ip_and_uri_finder = CommonAnalysisIPAndURIFinder()
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
				data = self.get_domains_from_uri(data)
				final_data[data] = {}
				final_data[data]['dns'] = self.get_ips_from_domain(data)
				final_data[data]['whois'] = self.get_domain_whois(data)
			else:
				final_data[data] = {}
				final_data[data]['dns'] = self.get_domains_from_ip(data)
				final_data[data]['whois'] = self.get_ip_whois(data)


		file_object.processed_analysis[self.NAME] = final_data
		return file_object
		
	def is_ip(self,data):
		try:
			ip_address(data)
			return True
		except:
			return False

			
	def get_ip_whois(self, ip):
		try:
			result = pprint.pformat(IPASN(Net(ip)).lookup())
			return result
		except Exception as e:
			return "No data found, or asset is not a web host"
		
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
			return pprint.pformat(data_dict)
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
		
	
	



