import requests
ip="8.8.8.8"
url = "https://ipxapi.com/api/ip?ip=ip"
headers = {
                    'Accept': "application/json",
                    'Content-Type': "application/json",
                    'Authorization': "Bearer 1805|KccZsz40nbQDTpWWUrLybpJjlcbUeLLfYoAATfTm",
                    'cache-control': "no-cache"
           }
def ipxapi(ips):
	dic={}
	try:
		for i in ips:
			querystring={'ip':i}
			response = requests.request("GET", url=url, headers=headers, params=querystring)
			dic[i]={}
			dic[i]=response.text
		return (dic)
	except e:
		print('Error',e)
ips=['8.8.8.8', '2.58.56.14']
op=ipxapi(ips)

for i in op.items():
	print (i)