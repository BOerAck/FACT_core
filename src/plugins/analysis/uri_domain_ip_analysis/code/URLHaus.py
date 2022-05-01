from ipaddress import ip_address
from dns import resolver
import whois
import requests
import io
import pandas as pd
from zipfile import ZipFile
import time, pprint, datetime
from ipwhois.net import Net
from ipwhois.asn import IPASN

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	NAME = 'URLHaus_Analysis'
	DEPENDENCIES = ['ip_and_uri_finder']
	DESCRIPTION = (
	'Downloads and Unzips latest URLHause CSV file. Checks for string matches between all domains/IPs/URIs within all URLHaus URLs. Expect 10-20 seconds per lookup. No API key required'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		self.ip_and_uri_finder = CommonAnalysisIPAndURIFinder()
		super().__init__(plugin_administrator, config=config, recursive=recursive, timeout=timeout, plugin_path=__file__)

	def process_object(self, file_object):
		final_data = {} #dict of original artifact mapped to analysis
		result = self.ip_and_uri_finder.analyze_file(file_object.file_path, separate_ipv6=True)
		for key in ['uris', 'ips_v4', 'ips_v6']:
		    result[key] = self.remove_duplicates(result[key])
		self.init_urlhaus()
		for key, data_list in result.items():
			if key not in ['uris', 'ips_v4', 'ips_v6']:
				continue
			for data in data_list:
				final_data[data] = {}
				if key == 'uris':
					final_data[data]['URLHausURI'] = self.URLHaus_check(data)
				
					data = self.get_domains_from_uri(data)
					final_data[data] = {}
					final_data[data]['URLHausDomain'] = self.URLHaus_check(data)
					domains_to_ips = self.get_ips_from_domain(data)
					for ip in domains_to_ips:
						final_data[data][f'URLHaus {data} to_ip: {ip}'] = self.URLHaus_check(ip)

				elif key == 'ips_v4':
					final_data[data]['URLHausIP'] = self.URLHaus_check(data)
					ips_to_domains = self.get_domains_from_ip(data)
					for domain in ips_to_domains:
						final_data[data][f'URLHaus {data} to_domain: {domain}'] = self.URLHaus_check(domain)

		file_object.processed_analysis[self.NAME] = final_data
		return file_object
		
	def init_urlhaus(self):
		url = "https://urlhaus.abuse.ch/downloads/csv/"
		response = requests.get(url)
		tempfile = io.BytesIO(response.content)
		input_zip=ZipFile(tempfile)
		d = {name: input_zip.read(name) for name in input_zip.namelist()}
		csv = d['csv.txt']
		tempfile = io.BytesIO(csv)
		tempfile.seek(0)
		pcsv = pd.read_csv(tempfile,on_bad_lines='skip',skiprows = [i for i in range(0, 8) ])
		self.urlhaus_csv = pcsv
		
		
	def URLHaus_check(self, value):
		return_dict = {'count':0,'last_match':{}}
		for index, row in self.urlhaus_csv.iterrows():
			url = row['url']
			if value in url:
				return_dict['count'] += 1
				return_dict['last_match'] = self.urlhaus_csv.loc[index].to_dict()
		return return_dict
		
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
	




