import requests
from ipaddress import ip_address
from dns import resolver
import whois
import requests
import time, pprint, datetime
from ipwhois.net import Net
from ipwhois.asn import IPASN
from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	NAME = 'IPX API analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	MIME_WHITELIST = ['text/plain', 'application/octet-stream', 'application/x-executable', 'application/x-object','application/x-sharedlib', 'application/x-dosexec']
	DESCRIPTION = (
	'Returns the results of API queries to AbuseIPDB 3rd party data source'
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
			final_data[data] = {}
			final_data[data]['IPxAPI'] = self.ipxapi([data])
		file_object.processed_analysis[self.NAME] = final_data
		return file_object
	
	def is_ip(self,data):
		try:
			ip_address(data)
			return True
		except:
			return False


		

	

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
	


	def ipxapi(self, ips):
		url = "https://ipxapi.com/api/ip?ip=ip"
		headers = {
						'Accept': "application/json",
						'Content-Type': "application/json",
						'Authorization': "Bearer 1875|nSH4Efr3h6T9kJytFOzSpsYjTjzpkMAVd6bkmB3y",
						'cache-control': "no-cache"
		}
		dic={}
		try:
			for i in ips:
				querystring={'ip':i}
				response = requests.request("GET", url=url, headers=headers, params=querystring)
				dic[i]={}
				dic[i]=response.text
			return (pprint.pformat(dic))
		except Exception as e:
			return(pprint.pformat{"ipxapierror"})