import requests


# Defining the api-endpoint
url = 'https://api.abuseipdb.com/api/v2/check'
headers = {'Key': '339fff1dc437c2ff9d54cc0b631998254d9378ee1b366a7d0ea59f95385a160188cadf80a95ee151'}



# Formatted output
def apii(ip):
	dic={}
	try:
		for i in ip:
			querystring = {'ipAddress': i,'maxAgeInDays': '90'}
			response = requests.request(method='GET', url=url, headers=headers, params=querystring)
			dic[i]={}
			dic[i]= response.text
		return (dic)
	except e:
		print('Error',e)

ip= ['8.8.8.8', '2.58.56.14']
outp=apii(ip)


for i in outp.items():
	print(i)

