"""Browser acceptance using only synthetic data; never contacts a deployed SIEM.

Run: python tests/browser/console_smoke.py [--screenshots DIRECTORY]
Requires: pip install playwright; python -m playwright install chromium
"""
import argparse
import json, mimetypes
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[2] / 'mobile' / 'soc'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--screenshots',type=Path)
args=parser.parse_args()
OUT=args.screenshots or Path(tempfile.mkdtemp(prefix='soc-browser-'))
OUT.mkdir(parents=True,exist_ok=True)
checks=[]
fixtures={
 '/me':{'user':'demo-analyst'},
 '/kpis':{'kpis':{'incidents_critiques_7j':3,'hotes_risque_ueba':8,'alertes_24h':1246,'kev_exposees':2}},
 '/timeseries':{'series':[{'t':f'2026-11-20T{h:02}:00:00Z','n':v} for h,v in enumerate([12,19,8,15,22,40,58,85,66,110,95,143])]},
 '/by-tactic':{'data':[{'k':'Initial Access','n':183},{'k':'Credential Access','n':95},{'k':'Discovery','n':67}]},
 '/top-detections':{'data':[{'k':'Brute force','n':125},{'k':'Firewall denied','n':95},{'k':'Admin login','n':43}]},
 '/top-sources':{'data':[{'k':'WatchGuard','n':1642},{'k':'UniFi','n':890},{'k':'Palo Alto','n':1052}]},
 '/cases':{'cases':[{'id':'demo-1','severity':'high','status':'new','title':'Authentifications répétées depuis une adresse externe','ts':'2026-11-20T08:12:00Z','entities':'demo-account','mitre':'T1110'},{'id':'demo-2','severity':'medium','status':'in_progress','title':'Modification de la configuration réseau','ts':'2026-11-20T08:05:00Z','entities':'demo-switch','mitre':'T1562'}]},
 '/attack-matrix':{'matrix':[]},'/detections':{'items':[]},
 '/network':{'days':7,'aruba':{'total':4,'switches_seen':1}},
 '/entity-search':{'results':[{'entity':'demo-account','kind':'user','n':42}]},
 '/search':{'total':1,'results':[{'ts':'2026-11-20T08:12:00Z','src':'WatchGuard','msg':'Fixture: authentication rejected for demo-account','host':'demo-firewall','ip':'192.0.2.20'}]},
 '/health':{'cluster':'green','events_24h':3584,'nodes':1,'shards':12,'sources':[{'k':'WatchGuard','n':1642,'last':'2026-11-20T08:12:00Z'},{'k':'UniFi','n':890,'last':'2026-11-20T08:11:00Z'},{'k':'Palo Alto','n':1052,'last':'2026-11-20T08:10:00Z'}]},
 '/siem-ops':{'status':'ok','items':[]},'/vapid':{},'/risk':{'threat_level':'SURVEILLE'},'/guidance':{'guidance':{'fixture':{'ce_que_cest':'Fixture'}}},
}

with sync_playwright() as p:
 browser=p.chromium.launch(headless=True)
 for width,height in [(1440,1000),(1024,900),(390,844)]:
  for theme in ['dark','light']:
   context=browser.new_context(viewport={'width':width,'height':height},service_workers='block')
   context.add_init_script('localStorage.setItem("soc_theme",'+json.dumps(theme)+');localStorage.setItem("soc_lang","fr");')
   page=context.new_page(); errors=[]; mode={'value':'ok'}
   page.on('pageerror',lambda e:errors.append(str(e)))
   def route(r):
    path=urlsplit(r.request.url).path
    if path.startswith('/m/api/'):
     if mode['value']=='error' and path=='/m/api/risk':return r.fulfill(status=503,content_type='application/json',body='{"available":false}')
     if mode['value']=='network_error' and path=='/m/api/network':return r.fulfill(status=503,content_type='application/json',body='{"available":false}')
     headers={'X-SOC-Cache':'1795161600000'} if mode['value']=='cached' and path=='/m/api/kpis' else {}
     return r.fulfill(status=200,headers=headers,content_type='application/json',body=json.dumps(fixtures.get(path[6:],{})))
    if path=='/soc/':path='/soc/index.html'
    file=ROOT/path.removeprefix('/soc/')
    if file.is_file():return r.fulfill(status=200,content_type=mimetypes.guess_type(file.name)[0] or 'application/octet-stream',body=file.read_bytes())
    return r.fulfill(status=404,body='not found')
   page.route('**/*',route)
   page.goto('http://127.0.0.1/soc/')
   page.wait_for_selector('#app',state='visible')
   page.wait_for_timeout(700)
   page.evaluate('''()=>{window.fixtureErrors=[];for(const n of ["renderKpis","renderTs","renderTac","renderDet","renderSrc","renderMatrix","renderCases","renderHealth","renderRisk"]){const fn=window[n];window[n]=function(){try{return fn.apply(this,arguments)}catch(e){window.fixtureErrors.push(n+": "+e.stack);throw e;}}}}''')
   page.screenshot(path=str(OUT/f'overview-{width}-{theme}.png'),full_page=True)
   assert page.locator('#kpis .kpi').count()==4
   assert page.locator('.pro-nav-label').count()==4
   assert page.locator('html').evaluate('(e)=>e.scrollWidth<=innerWidth'), 'document horizontal overflow'
   assert page.locator('main').evaluate('(e)=>e.scrollWidth<=e.clientWidth+1'), 'main horizontal overflow'
   page.locator('#pro-search-input').fill('demo-account')
   page.locator('.pro-searchbar button').click()
   page.wait_for_selector('#pal.on')
   assert page.locator('#palIn').input_value()=='demo-account'
   page.locator('#palList .pi').filter(has_text='dans les logs').click()
   page.wait_for_selector('#palList',state='visible')
   page.wait_for_timeout(150)
   assert 'Fixture:' in page.locator('#palList').inner_text()
   page.keyboard.press('Escape')
   page.locator('.pro-heading-actions button').nth(1).click()
   page.wait_for_timeout(120)
   assert page.locator('#p-health').is_visible()
   assert 'WatchGuard' in page.locator('#hsrc').inner_text()
   assert 'UniFi' in page.locator('#hsrc').inner_text()
   assert 'Palo Alto' in page.locator('#hsrc').inner_text()
   if width>820:
    page.locator('#nav a[data-p=incidents]').click()
   else:
    page.locator('#bnav [data-bp=incidents]').click()
   page.wait_for_timeout(120)
   assert page.locator('.pro-page-title').inner_text()=='Incidents'
   assert page.locator('#nav a[aria-current=page]').get_attribute('data-p')=='incidents'
   row=page.locator('#incFeed .inc').first
   row.evaluate('(el)=>{window.rowClicks=0;el.addEventListener("click",()=>window.rowClicks++)}')
   row.focus();page.keyboard.press('Enter')
   assert page.evaluate('window.rowClicks')==1, 'keyboard activated incident more than once'
   page.keyboard.press('Escape')
   page.screenshot(path=str(OUT/f'incidents-{width}-{theme}.png'),full_page=True)
   if width>820:
    page.locator('#langBtn').click()
   else:
    page.locator('#bMore').click()
    page.locator('#shBody button[data-onclick="setLang(\'en\')"]').click()
    page.keyboard.press('Escape')
   page.wait_for_timeout(120)
   assert page.locator('.pro-nav-label').first.inner_text().lower()=='monitoring'
   assert page.locator('.pro-searchbar button').inner_text()=='Search'
   page.keyboard.press('Control+k');page.wait_for_selector('#pal.on');page.keyboard.press('Escape')
   def navigate_network():
    if width>820:page.locator('#nav a[data-p=network]').click()
    else:
     page.locator('#bMore').click()
     page.locator('#shBody button[data-onclick="goNav(\'network\')"]').click()
    page.wait_for_timeout(180)
   navigate_network()
   assert 'Aruba' in page.locator('#netWrap').inner_text()
   mode['value']='network_error';navigate_network()
   assert 'data unavailable for this view' in page.locator('.pro-context').inner_text().lower()
   assert page.locator('#p-network').evaluate('(e)=>e.classList.contains("view-stale")')
   # Core requests can succeed while the optional view remains unavailable.
   page.locator('#netbar button').click() if page.locator('#netbar').is_visible() else page.locator('#refBtn').click()
   page.wait_for_timeout(180)
   assert 'data unavailable for this view' in page.locator('.pro-context').inner_text().lower()
   mode['value']='ok';navigate_network()
   assert 'data unavailable for this view' not in page.locator('.pro-context').inner_text().lower()
   assert not page.locator('#p-network').evaluate('(e)=>e.classList.contains("view-stale")')
   mode['value']='error'
   page.locator('#refBtn').click()
   page.wait_for_timeout(180)
   assert page.locator('body').evaluate('(e)=>e.classList.contains("data-stale")')
   assert page.locator('#tlabel').inner_text()=='UNAVAILABLE'
   assert 'failed' in page.locator('.pro-context').inner_text().lower()
   mode['value']='ok'
   page.locator('#netbar button').click() if page.locator('#netbar').is_visible() else page.locator('#refBtn').click()
   page.wait_for_timeout(350)
   assert not page.locator('body').evaluate('(e)=>e.classList.contains("data-stale")')
   mode['value']='cached';page.locator('#refBtn').click();page.wait_for_timeout(180)
   assert page.locator('body').evaluate('(e)=>e.classList.contains("data-stale")')
   assert 'cached' in page.locator('.pro-context').inner_text().lower()
   assert not page.evaluate('window.fixtureErrors'), page.evaluate('window.fixtureErrors')
   assert not errors, errors
   checks.append({'width':width,'theme':theme,'errors':errors,'passed':True})
   context.close()
 browser.close()
print(json.dumps(checks,indent=2))
