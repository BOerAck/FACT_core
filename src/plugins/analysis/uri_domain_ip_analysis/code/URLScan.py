from ipaddress import ip_address
from dns import resolver
import whois
import requests
import time, pprint, datetime, json
from ipwhois.net import Net
from ipwhois.asn import IPASN

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	NAME = 'URLScan_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	DESCRIPTION = (
	'Submits scan URL/IP requests to URLScan.io, returns URL which will contain scan results. API key required.'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		self.api_key = "3ef72918-da86-4e23-a971-7e368f5d8fb6"
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
					final_data[data] = {}
					final_data[data]['URLScanURL'] = self.submit_urlscan(data)
					domains_to_ips = self.get_ips_from_domain(data)
					for ip in domains_to_ips:
						final_data[data][f'URLScan {data} to_ip: {ip}'] = self.submit_urlscan(ip)

				elif key == 'ips_v4':
					final_data[data] = {}
					final_data[data]['URLScanIP'] = self.submit_urlscan(data)
					ips_to_domains = self.get_domains_from_ip(data)
					for domain in ips_to_domains:
						final_data[data][f'URLScan {data} to_domain: {domain}'] = self.submit_urlscan(domain)
		file_object.processed_analysis[self.NAME] = final_data
		return file_object
		
			
	def submit_urlscan(self,data):
		try:
			data = {"url": data, "visibility": "public"}
			headers = {'API-Key':self.api_key,'Content-Type':'application/json'}
			response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
			return pprint.pformat(response.json())
		except:
			return {"ERROR":data}

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
	



