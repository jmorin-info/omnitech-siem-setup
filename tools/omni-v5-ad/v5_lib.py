#!/usr/bin/env python3
# OMNITECH SIEM v5 - chantier 1 (detections AD et M365) - fonctions communes. Aucun secret affiche ni ecrit.
import base64, http.client, json, re, ssl, urllib.request, urllib.error
http.client._MAXHEADERS = 10000
VARS = "/root/omnitech-siem-setup/00-vars.env"
env = {}
for l in open(VARS, encoding="utf-8"):
    m = re.match(r'^(?:export\s+)?([A-Z_]+)=["\']?([^"\'\n]*)', l)
    if m: env[m.group(1)] = m.group(2)
API = "https://127.0.0.1:9000/api"
OS = "http://127.0.0.1:9200"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
_tok = env.get("GRAYLOG_API_TOKEN", "")
_ident = f"{_tok}:token" if _tok else f"admin:{env.get('GRAYLOG_ADMIN_PASS', '')}"
AUTH = "Basic " + base64.b64encode(_ident.encode()).decode()

def api(meth, path, body=None, timeout=120):
    req = urllib.request.Request(API + path, method=meth, data=(json.dumps(body).encode() if body is not None else None),
                                 headers={"Authorization": AUTH, "Content-Type": "application/json", "Accept": "application/json", "X-Requested-By": "omni-v5-ad"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            t = r.read().decode(); return json.loads(t) if t else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{meth} {path} -> {e.code} {e.read().decode()[:600]}")

def osq(path, body=None, meth=None, timeout=300):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(OS + path, data=data, method=meth or ("POST" if data else "GET"), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            t = r.read().decode(); return json.loads(t) if t.strip().startswith(("{", "[")) else t
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"OS {path} -> {e.code} {e.read().decode()[:600]}")

def total(r):
    t = r["hits"]["total"]; return t["value"] if isinstance(t, dict) else t
