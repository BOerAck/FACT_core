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
	NAME = 'AlienVault_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	DESCRIPTION = (
	'Returns the results of DNS and WHOIS queries for identified IPS and URIs'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		self.domains_from_uris = 0
		self.ips_from_domains = 0
		self.domains_from_ips = 0
		self.alien_ip = 0
		self.alien_domain = 0
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
					final_data['AlienVaultDomain'] = {}
					final_data['AlienVaultDomain'][data] = self.alienDomain([data])
					domains_to_ips = self.get_ips_from_domain(data)
					for ip in domains_to_ips:
						final_data['AlienVaultDomain'][f'{data} to_ip: {ip}'] = self.alienvaultIp([ip])

				elif key == 'ips_v4':
					final_data['AlienVaultIP'] = {}
					final_data['AlienVaultIP'][data] = self.alienvaultIp([data])
					ips_to_domains = self.get_domains_from_ip(data)
					for domain in ips_to_domains:
						final_data['AlienVaultIP'][f'{data} to_domain: {domain}'] = self.alienDomain([domain])
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
			
	#IP Part using ALienVault
	def alienvaultIp(self, IP):
		return_dict= {}
		try:
			for ip in IP:
				self.alien_ip += 1
				url_ip="https://otx.alienvault.com/api/v1/indicators/IPv4/"+ip+"/geo"
				response=requests.get(url_ip)

				if(response.status_code==200):
					geo_dict=response.json()
					return_dict = {"asn":geo_dict['asn'],'continent':geo_dict['continent_code'],'latitude':geo_dict['latitude'],'longitude':geo_dict['longitude'],'country':geo_dict['country_name']}
					#print(geo_dict)
					""" print("\nAnalyzing the IPs via various sources......\n")
					print("\nIP Address being Analyzed: " + str(ip) + "\n")
					print("ASN: " + geo_dict['asn'])
					print("Continent: " + geo_dict['continent_code'])
					print("Latitude: " + str(geo_dict['latitude']) + " and Longitude: " + str(geo_dict['longitude']))
					print("Country: " + geo_dict['country_name']) """
					return(pprint.pformat(return_dict))

				else:
					return{"Response_Status": str(response.status_code)}
		except Exception as e:
			return {"AlienVault Error":f"ERROR: {e}"}

		
	def alienDomain(self, Domains):
		try:
			for domain in Domains:
				self.alien_domain += 1
				url_domain= "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/geo"
				response_domain=requests.get(url_domain)

				if(response_domain.status_code==200):
					geo_dict=response_domain.json()
					return_dict = {'asn':geo_dict['asn'],'continent':geo_dict['continent_code'],'latitude':str(geo_dict['latitude']),'longitude':str(geo_dict['longitude']),'country':geo_dict['country_name']}
					""" print("\nAnalyzing the Domains via various sources......\n")
					print("\nDomain Name being Analyzed: " + str(domain) + "\n")
					print("ASN: " + geo_dict['asn'])
					print("Continent: " + geo_dict['continent_code'])
					print("Latitude: " + str(geo_dict['latitude']) + " and Longitude: " + str(geo_dict['longitude']))
					print("Country: " + geo_dict['country_name']) """
					return(pprint.pformat(return_dict))

				else:
					return{"Response_Status":str(response_domain.status_code)}
		except Exception as e:
			return {"AlienVault Error":f"ERROR: {e}"}
	
	@staticmethod
	def _remove_duplicates(input_list):
		return list(set(input_list))
	
	def get_summary(self):
		return {'domains_from_uris':self.domains_from_uris,'ips_from_domains':self.ips_from_domains,'domains_from_ips':self.domains_from_ips,'alien_ip':self.alien_ip,'alien_domain':self.alien_domain}





