from ipaddress import ip_address
from dns import resolver
import whois
import requests
import time, pprint, datetime
from requests.auth import HTTPBasicAuth
from ipwhois.net import Net
from ipwhois.asn import IPASN

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	NAME = 'XForce_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	DESCRIPTION = (
	'Returns the results of DNS and WHOIS queries for identified IPS and URIs'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		self.domains_from_uris = 0
		self.ips_from_domains = 0
		self.domains_from_ips = 0
		self.xforce_ip = 0
		self.xforce_domain = 0
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
					final_data['XForceURI'] = {}
					final_data['XForceURI'][data] = self.xforceDomain([data])
					
					data = self.get_domains_from_uri(data)
					final_data['XForceDomain'] = {}
					final_data['XForceDomain'][data] = self.xforceDomain([data])
					domains_to_ips = self.get_ips_from_domain(data)
					for ip in domains_to_ips:
						final_data['XForceDomain'][f'{data} to_ip: {ip}'] = self.xforceIp([ip])

				elif key == 'ips_v4':
					final_data['XForceIP'] = {}
					final_data['XForceIP'][data] = self.xforceIp([data])
					ips_to_domains = self.get_domains_from_ip(data)
					for domain in ips_to_domains:
						final_data['XForceIP'][f'{data} to_domain: {domain}'] = self.xforceDomain([domain])
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

	# Domain/URL Part using X-Force 
	# This part below can also analyze the URLs along with the domain names
	def xforceDomain(self, Domains):
		try:
			for domain in Domains:
				self.xforce_domain += 1
				url_ip_history="https://api.xforce.ibmcloud.com/api/url/" + domain
				auth = HTTPBasicAuth('596dda3c-5763-46f4-a8a0-82b6c27bdb75', 'd83c4aef-fc33-4f6d-874a-61d3a7574735')
				response = requests.get(url_ip_history, auth = auth)

				if(response.status_code==200):
					data_url=response.json()
					return_dict={'domain_category':str(data_url['result']['cats']),'threat_score':str(data_url['result']['score']),'description':str(data_url['result']['categoryDescriptions']['Search Engines / Web Catalogues / Portals'])}
					""" print("\nInformation and Threat Level of URLs and Domains\n")
					print("Category of URL/Domain: " + str(data_url['result']['cats']) + "\n",
					"Threat Score: " + str(data_url['result']['score']) + "\n",
					"Description: " + str(data_url['result']['categoryDescriptions']['Search Engines / Web Catalogues / Portals']) + "\n")
					print("\n====================================================\n") """
					return(pprint.pformat(return_dict))
				else:
					return{"Response_Status":str(response.status_code)}	
		except Exception as e:
			return {"XForce Error":f"ERROR: {e}"}

	# IP Part Using X-Force
	def xforceIp(self, IP):
		try:
			for ip in IP:
				self.xforce_ip += 1
				url_ip_history="https://api.xforce.ibmcloud.com/api/ipr/history/" + ip
				auth = HTTPBasicAuth('596dda3c-5763-46f4-a8a0-82b6c27bdb75', 'd83c4aef-fc33-4f6d-874a-61d3a7574735')
				response = requests.get(url_ip_history, auth = auth)

				if(response.status_code==200):
					resp_ip_history=response.json()
					l=len(resp_ip_history['history'])
					#print("\n History of IP: " + str(ip) + "\n")

					for i in range(l):
						return_dict = {'date_of_record':str(resp_ip_history['history'][i]['created']),'location':str(resp_ip_history['history'][i]['geo']['country']),'category':str(resp_ip_history['history'][i]['categoryDescriptions']),'description':str(resp_ip_history['history'][i]['reasonDescription']),'threat_score':str(resp_ip_history['history'][i]['score'])}
						""" print("Date of Record: " + str(resp_ip_history['history'][i]['created']) + "\n",
						"Location: " + str(resp_ip_history['history'][i]['geo']['country']) + "\n", 
						"Category: " + str(resp_ip_history['history'][i]['categoryDescriptions']) + "\n",
						"Description: " + str(resp_ip_history['history'][i]['reasonDescription']) + "\n",
						"Threat Score out of 10 (Higher is More Severe): " + str(resp_ip_history['history'][i]['score'])+"\n")

						print("\n=================================================\n") """
					return(pprint.pformat(return_dict))

				else:
					return{"Response_Status":str(response.status_code)}
		except Exception as e:
			return {"XForce Error":f"ERROR: {e}"}

	
	
	
	@staticmethod
	def _remove_duplicates(input_list):
		return list(set(input_list))
	
	def get_summary(self):
		return {'domains_from_uris':self.domains_from_uris,'ips_from_domains':self.ips_from_domains,'domains_from_ips':self.domains_from_ips,'xforce_ip':self.xforce_ip,'xforce_domain':self.xforce_domain}





