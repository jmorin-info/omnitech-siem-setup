import http.client, json, ssl, base64, sys, urllib.request
http.client._MAXHEADERS = 10000
env={}
for l in open('/root/omnitech-siem-setup/00-vars.env'):
    l=l.strip()
    if '=' in l and not l.startswith('#'):
        k,v=l.split('=',1); env[k.replace('export ','').strip()]=v.strip().strip('"').strip("'")
auth=base64.b64encode(('admin:'+env['GRAYLOG_ADMIN_PASS']).encode()).decode()
ctx=ssl._create_unverified_context()
def api(path, method='GET', data=None):
    req=urllib.request.Request('https://127.0.0.1:9000/api'+path, method=method, data=(json.dumps(data).encode() if data is not None else None))
    req.add_header('Authorization','Basic '+auth); req.add_header('Accept','application/json'); req.add_header('X-Requested-By','v5-collecte')
    if data is not None: req.add_header('Content-Type','application/json')
    with urllib.request.urlopen(req, context=ctx, timeout=120) as r:
        b=r.read(); return json.loads(b) if b else {}
