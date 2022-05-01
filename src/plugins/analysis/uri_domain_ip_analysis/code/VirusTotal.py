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
	NAME = 'Virustotal_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	DESCRIPTION = (
	'Returns the results of DNS and WHOIS queries for identified IPS and URIs'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		self.domains_from_uris = 0
		self.ips_from_domains = 0
		self.domains_from_ips = 0
		self.virustotal_ip = 0

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
					final_data['VirusTotalDomain_to_IP'] = {}
					domains_to_ips = self.get_ips_from_domain(data)
					for ip in domains_to_ips:
						final_data['VirusTotalDomain_to_IP'][f'{data} to_ip: {ip}'] = self.virustotalIp([ip])

				elif key == 'ips_v4':
					final_data['VirusTotalIP'] = {}
					final_data['VirusTotalIP'][data] = self.virustotalIp([data])
					#ips_to_domains = self.get_domains_from_ip(data)
					#for domain in ips_to_domains:
						#final_data['AlienVaultIP'][f'{data} to_domain: {domain}'] = self.alienDomain([domain])
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
			
	# IP Part using VirusTotal
	def virustotalIp(self,IP):
		return_dict = {}
		try:
			for ip in IP:
				self.virustotal_ip += 1
				header={ "X-Apikey": "898e54e360cdf32b5714e2d14d3881d6c0274f21a791d972244a4ebe86b2e711"}
				url="https://www.virustotal.com/api/v3/ip_addresses/" + ip
				response_ip_rep=requests.get(url, headers=header)

				if(response_ip_rep.status_code==200):
					ip_rep=response_ip_rep.json()
					#print(ip_rep)

					return_dict = {'harmless':str(ip_rep['data']['attributes']['last_analysis_stats']['harmless']),'malicious':str(ip_rep['data']['attributes']['last_analysis_stats']['malicious']),'suspicious':(str(ip_rep['data']['attributes']['last_analysis_stats']['suspicious'])),'undetected':str(ip_rep['data']['attributes']['last_analysis_stats']['undetected'])}
					"""
					print("\nIP Reputation from various AVs:\n") 
					print("Harmless: " + str(ip_rep['data']['attributes']['last_analysis_stats']['harmless']))
					print("Malicious: " + str(ip_rep['data']['attributes']['last_analysis_stats']['malicious']))
					print("Suspicious: " + str(ip_rep['data']['attributes']['last_analysis_stats']['suspicious']))
					print("Undetected: " + str(ip_rep['data']['attributes']['last_analysis_stats']['undetected'])) """
					return(pprint.pformat(return_dict))

				else:
					return{"Response_Status":str(response_ip_rep.status_code)}
	
		except Exception as e:
			return {"VirusTotal Error":f"ERROR: {e}"}
	
	
	@staticmethod
	def _remove_duplicates(input_list):
		return list(set(input_list))
	
	def get_summary(self):
		return {'ips_from_domains':self.ips_from_domains,'virustotal_ip':self.virustotal_ip}





