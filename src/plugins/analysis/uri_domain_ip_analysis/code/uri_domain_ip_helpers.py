from ipaddress import ip_address
from dns import resolver

def get_domains_from_uri(self, uri):
	try:
		sub_strs = uri.split("://")
		if len(sub_strs) == 1: #case where no protocol
			domain = (sub_strs[0])
		else:
			domain = (sub_strs[1].split("/")[0])
		return domain
	except:
		return None
		

def get_ips_from_domain(self, domain):
	try:
		ips = []
		response = resolver.resolve(domain,'A')
		for ip in response:
			ips.append(str(ip))
		return ips
	except:
		return [None]

def get_domains_from_ip(self, ip):
	try:
		domains = []
		#print(f'requesting {ip}')
		response = resolver.resolve_address(ip)
		for domain in response:
			domains.append(str(domain))
		return domains
	except Exception as e:
		return [None]
		
		
def remove_duplicates(input_list):
	return list(set(input_list))
