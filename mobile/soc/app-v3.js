/* OMNITECH-SOC-20261112 : console v3 — PWA (service worker, notifications, hors ligne, installation),
   navigation mobile (barre du bas + menu), routage par ancre (#p=page&e=entité&case=id),
   filtres des incidents, pastilles, états de chargement et d'erreur, état réel du SIEM dans l'en-tête. */
(function(){
"use strict";
var V3="v3 · 12/11/2026";
try{SOC_BUILD="v3 · build 2026-11-12";}catch(e){}
var q1=function(s){return document.querySelector(s);};
var EN=function(){try{return LANG==="en";}catch(e){return false;}};
var T=function(fr,en){return EN()?en:fr;};
var LS={get:function(k){try{return localStorage.getItem(k);}catch(e){return null;}},
        set:function(k,v){try{if(v==null)localStorage.removeItem(k);else localStorage.setItem(k,v);}catch(e){}}};
function appOn(){var a=q1("#app");return !!a&&a.style.display==="grid";}
function curPage(){var a=document.querySelector("#nav a.on");return a?a.getAttribute("data-p"):"overview";}

/* ---------- descriptions des pages SOAR et Exploitation ---------- */
try{
  PDESC.fr.soar="<b>SOAR — blocages pare-feu</b> — IP publiques bloquées automatiquement par les FortiGate (Bordeaux et Ivry) après une détection WAF. Levée automatique à 24 h ; <b>Débloquer</b> dépose une demande journalisée, traitée en moins d'une minute.";
  PDESC.fr.ops="<b>Exploitation du SIEM</b> — mises à jour automatiques, redémarrage en attente, snapshots et test de restauration, sauvegarde, disques, services en échec, certificat. Vert : rien à faire.";
  PDESC.en.soar="<b>SOAR — firewall blocks</b> — public IPs blocked automatically by the FortiGates (Bordeaux and Ivry) after a WAF detection. Lifted after 24 h; <b>Unblock</b> files a logged request, processed within a minute.";
  PDESC.en.ops="<b>SIEM operations</b> — automatic updates, pending reboot, snapshots and restore test, backup, disks, failed services, certificate. Green: nothing to do.";
}catch(e){}

/* ---------- réseau : hors ligne et données en cache ---------- */
var NET={off:false,cacheAt:0};
function fmtWhen(t){try{return new Date(t).toLocaleString(EN()?"en-GB":"fr-FR",{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit"});}catch(e){return "";}}
function netRender(){var b=q1("#netbar");if(!b)return;
  if(!NET.off){b.classList.remove("on");document.body.classList.remove("offline");return;}
  var msg;
  if(NET.cacheAt){var m=Math.max(0,Math.round((Date.now()-NET.cacheAt)/60000));
    var age=m<1?T("à l'instant","just now"):m<120?T("il y a "+m+" min",m+" min ago"):T("il y a "+Math.round(m/60)+" h",Math.round(m/60)+" h ago");
    msg=T("Hors ligne — données du ","Offline — data from ")+fmtWhen(NET.cacheAt)+" ("+age+"). "+T("Actions désactivées.","Actions disabled.");}
  else msg=T("SIEM injoignable — vérifiez le réseau ou le VPN.","SIEM unreachable — check your network or VPN.");
  b.querySelector(".nbt").textContent=msg;var bt=b.querySelector("button");if(bt)bt.textContent=T("Réessayer","Retry");
  b.classList.add("on");document.body.classList.add("offline");}
function setOnline(){if(NET.off){NET.off=false;NET.cacheAt=0;netRender();}}
function setOffline(at){NET.off=true;if(at)NET.cacheAt=NET.cacheAt?Math.min(NET.cacheAt,at):at;netRender();}
setInterval(function(){if(NET.off)netRender();},60000);
window.addEventListener("offline",function(){setOffline(0);});
window.addEventListener("online",function(){socRetry();});
window.socRetry=function(){if(appOn()){try{refreshNow();}catch(e){}}else{j("/me").then(function(d){if(d&&d.user)start();}).catch(function(){});}};
function purgeData(){
  try{if(window.caches)caches.delete("soc-data-v1");}catch(e){}
  try{var c=navigator.serviceWorker&&navigator.serviceWorker.controller;if(c)c.postMessage({type:"purge-data"});}catch(e){}}
var _fetch=window.fetch;
window.fetch=function(input){
  var url=typeof input==="string"?input:((input&&input.url)||"");
  var p=_fetch.apply(window,arguments);
  if(url.indexOf("/m/api/")<0)return p;
  return p.then(function(r){
    var c=r.headers.get("X-SOC-Cache");
    if(c)setOffline(+c);else setOnline();
    if(r.status===401&&url.indexOf("/m/api/login")<0)purgeData();
    if(r.ok&&/\/m\/api\/siem-ops(\?|$)/.test(url))r.clone().json().then(updCluster).catch(function(){});
    return r;
  },function(e){setOffline(0);throw e;});
};
if(typeof logout==="function"){var _lo=logout;window.logout=function(){purgeData();try{if(navigator.clearAppBadge)navigator.clearAppBadge();}catch(e){}return _lo.apply(this,arguments);};}

/* ---------- état réel du SIEM dans la pastille de l'en-tête ---------- */
function updCluster(o){var d=document.querySelector("header .pill .dot");if(!d||!o)return;var pill=d.parentNode,lab=pill.querySelector("[data-i18n]");
  var st=o.status==="crit"?"crit":o.status==="warn"?"warn":"ok";
  d.className="dot"+(st==="ok"?"":" "+st);
  var n=(o.items||[]).filter(function(x){return x.status!=="ok";}).length;
  if(lab)lab.textContent=st==="ok"?T("SIEM opérationnel","SIEM operational"):st==="warn"?T("SIEM : à surveiller","SIEM: watch"):T("SIEM : critique","SIEM: critical");
  pill.title=T(n+" point(s) d'exploitation à regarder — ouvrir « Exploitation SIEM »",n+" operations item(s) to check — open “SIEM operations”");}
(function(){var d=document.querySelector("header .pill .dot");if(!d)return;var pill=d.parentNode;pill.classList.add("clu");pill.setAttribute("role","button");pill.setAttribute("tabindex","0");
  pill.addEventListener("click",function(){goNav("ops");});})();

/* ---------- routage par ancre : #p=page, #p=incidents&e=entité, #p=incidents&case=id ---------- */
var ROUTING=false,LASTH=location.hash,PENDING_CASE=null,STARTED=false;
function hashParams(){var o={};(location.hash||"").replace(/^#/,"").split("&").forEach(function(kv){var i=kv.indexOf("=");if(i>0){try{o[decodeURIComponent(kv.slice(0,i))]=decodeURIComponent(kv.slice(i+1));}catch(e){}}});return o;}
function navTo(p){if(CMDPAGES.indexOf(p)<0)p="overview";if(p===curPage())return;ROUTING=true;try{goNav(p);}finally{ROUTING=false;}}
function openCaseId(id){var i=-1;try{(CASES||[]).forEach(function(x,k){if(String(x.id)===String(id))i=k;});}catch(e){}
  if(i>=0){PENDING_CASE=null;openCase(i);}else PENDING_CASE=id;}
function route(full){if(!appOn())return;var o=hashParams();navTo(o.p||(o.e||o["case"]?curPage():"overview"));
  if(full&&o.e){try{openEntity(o.e,String(o.e).split("\\").pop());}catch(e){}}
  if(o["case"])openCaseId(o["case"]);
  if(o.e||o["case"]){var h="#p="+curPage();try{history.replaceState(null,"",h);}catch(e){}LASTH=h;}}
function onHash(){if(location.hash===LASTH)return;LASTH=location.hash;route(true);}
window.addEventListener("hashchange",onHash);window.addEventListener("popstate",onHash);
function openUrl(url){var i=String(url||"").indexOf("#"),h=i>=0?String(url).slice(i):"#p=incidents";if(location.hash===h){LASTH="";onHash();}else location.hash=h;}
var PAGE_WRAP={twin:"#twinWrap",ems:"#emsWrap",network:"#netWrap",deploy:"#depWrap"};
function afterNav(p){syncNav(p);socCloseSheet();var m=q1("main");if(m)m.scrollTop=0;
  try{document.title=((titles[LANG]||titles.fr)[p]||"Console")+" · OMNI SOC";}catch(e){}
  var sel=PAGE_WRAP[p];
  if(sel)setTimeout(function(){var w=q1(sel);if(w&&curPage()===p&&w.querySelector('p.muted[data-i18n$="_loading"]'))w.innerHTML='<div class="card">'+errBox(T("Page indisponible","Page unavailable"),"goNav('"+p+"')")+'</div>';},25000);
  if(p==="report")setTimeout(function(){var r=q1("#reportBody");if(r&&curPage()==="report"&&!r.innerHTML.trim())r.innerHTML=errBox(T("Rapport indisponible","Report unavailable"),"goNav('report')");},25000);}
document.addEventListener("click",function(e){var a=e.target&&e.target.closest?e.target.closest("#nav a[data-p]"):null;if(!a)return;
  var p=a.getAttribute("data-p");afterNav(p);
  if(!ROUTING){var want="#p="+p;if(location.hash!==want){try{history.pushState(null,"",want);}catch(_){location.hash=want;}LASTH=want;}}},false);

/* ---------- navigation mobile (barre du bas) et pastilles ---------- */
function syncNav(p){var inBar=false;
  document.querySelectorAll("#bnav [data-bp]").forEach(function(a){var on=a.getAttribute("data-bp")===p;if(on){a.setAttribute("aria-current","page");inBar=true;}else a.removeAttribute("aria-current");});
  var mo=q1("#bMore");if(mo){if(inBar)mo.removeAttribute("aria-current");else mo.setAttribute("aria-current","page");}}
function bnavI18n(){document.querySelectorAll("#bnav [data-fr]").forEach(function(s){s.textContent=EN()?s.getAttribute("data-en"):s.getAttribute("data-fr");});
  var c=document.querySelectorAll("#p-incidents .fchip");var L={open:["Ouverts","Open"],hot:["Critiques + élevés","Critical + high"],"new":["Non qualifiés","Untriaged"],all:["Tous","All"]};
  c.forEach(function(b){var l=L[b.getAttribute("data-f")];if(l)b.textContent=EN()?l[1]:l[0];});
  var qi=q1("#incQ");if(qi)qi.placeholder=T("Filtrer : titre, entité, technique, assigné…","Filter: title, entity, technique, assignee…");}
if(typeof setLang==="function"){var _sl=setLang;window.setLang=function(){var r=_sl.apply(this,arguments);bnavI18n();netRender();incFilter();if(q1("#sheet.on"))renderSheet();return r;};}
function badges(hot){var b=q1("#bbInc");if(b){if(hot>0){b.textContent=hot>99?"99+":String(hot);b.hidden=false;b.setAttribute("aria-label",hot+T(" incidents critiques ou élevés ouverts"," open critical or high incidents"));}else b.hidden=true;}
  var a=document.querySelector('#nav a[data-p="incidents"]');if(a){var s=a.querySelector(".navbadge");if(hot>0){if(!s){s=document.createElement("span");s.className="navbadge";a.appendChild(s);}s.textContent=hot>99?"99+":String(hot);}else if(s)s.remove();}
  try{if(navigator.setAppBadge){if(hot>0)navigator.setAppBadge(hot);else navigator.clearAppBadge();}}catch(e){}}

/* ---------- incidents : titre lisible (oms-xdr ne renseigne pas « title », seulement « rule ») ---------- */
var RULES={CR_RISKY_USER_ENDPOINT_THREAT:"Utilisateur à risque + menace sur le poste",CR_LSASS_THEFT:"Vol de la mémoire LSASS (identifiants)",
  CR_EXPOSED_SERVICE:"Service exposé attaqué",CR_PRIV_ESCALATION:"Élévation de privilèges",CR_CRED_ABUSE:"Abus d'identifiants (force brute puis succès)",
  CR_RANSOMWARE:"Comportement de rançongiciel",CR_CREDDUMP_PERSIST:"Vol d'identifiants + persistance",CR_CREDDUMP_LATERAL:"Vol d'identifiants + mouvement latéral",
  CR_AD_CERT_PERSIST:"Persistance par certificat AD",CR_AD_CREDENTIAL_THEFT:"Vol d'identifiants AD",CR_CREDUSE_ADMINSHARE:"Identifiants utilisés sur des partages d'administration",
  CR_DECEPTION_TRIGGERED:"Leurre déclenché",CR_DEFENSE_NEUTRALIZED:"Défenses neutralisées",CR_ENDPOINT_COMPROMISE:"Poste compromis",CR_ENDPOINT_MALWARE:"Logiciel malveillant sur un poste",
  CR_IMPOSSIBLE_TRAVEL_PIVOT:"Voyage impossible puis rebond",CR_LATERAL_FROM_SCAN:"Mouvement latéral après balayage",CR_LATERAL_MOVEMENT:"Mouvement latéral",
  CR_OFFENSIVE_PS_PERSIST:"PowerShell offensif + persistance",CR_PASSWORD_SPRAY_INTERNAL:"Pulvérisation de mots de passe (interne)",CR_RECON_TO_ACCESS:"Reconnaissance puis accès",
  CR_RISKY_USER_PRIV_ACTION:"Utilisateur à risque : action privilégiée",CR_SEAL_ACCOUNT_CHANGE:"Modification d'un compte SEAL",
  CR_ANOMALY_CONFIRMED_HOST:"Anomalie confirmée (hôte)",CR_ANOMALY_CONFIRMED_USER:"Anomalie confirmée (utilisateur)"};
function caseTitle(x){var r=String(x.rule||"");
  if(!EN()&&RULES[r])return RULES[r];
  var n=String(x.narrative||"").split("\n")[0].replace(/^Attaque probable\s*:\s*/i,"").replace(/\.$/,"");
  if(!EN()&&n&&n.length<=90)return n;
  return r?r.replace(/^CR_/,"").replace(/_/g," ").toLowerCase().replace(/^./,function(c){return c.toUpperCase();}):T("Incident corrélé","Correlated incident");}

/* ---------- en-tête compact (mobile) ---------- */
var MQ=window.matchMedia?matchMedia("(max-width:820px)"):null;
if(typeof tickUpd==="function"){var _tu=tickUpd;window.tickUpd=function(){var r=_tu.apply(this,arguments);
  try{if(MQ&&MQ.matches&&!RELOADING){var el=q1("#updPill .updtxt");if(el)el.textContent=fmtAgoShort(UPD_AT);}}catch(e){}return r;};}
(function(){var b=document.querySelector('header button[data-onclick="openPal()"]');if(b){b.id="palBtn";b.innerHTML=ic("search")+'<span class="kk">⌘K</span>';}})();

/* ---------- incidents : filtres ---------- */
var INCF=LS.get("soc_incf")||"open";
function isOpen(x){return x.status!=="closed"&&x.status!=="resolved";}
function incMatch(x,f,q){var sev=sevClass(x.severity);
  if(f==="open"&&!isOpen(x))return false;
  if(f==="hot"&&!(isOpen(x)&&(sev==="critical"||sev==="high")))return false;
  if(f==="new"&&x.status!=="new")return false;
  if(q){var s=[x.title,x.entities,x.mitre,x["assignée"],x.severity].join(" ").toLowerCase();if(s.indexOf(q)<0)return false;}
  return true;}
function incFilter(){var feed=q1("#incFeed");if(!feed)return;var list=[];try{list=CASES||[];}catch(e){}
  var q=((q1("#incQ")||{}).value||"").trim().toLowerCase();var shown=0;
  var rows=feed.querySelectorAll(":scope > .inc");
  for(var i=0;i<rows.length;i++){var x=list[i];var ok=!x||incMatch(x,INCF,q);rows[i].style.display=ok?"":"none";if(ok)shown++;}
  var none=feed.querySelector(".incnone");
  if(rows.length&&!shown){if(!none){none=document.createElement("div");none.className="empty incnone";feed.appendChild(none);}
    none.innerHTML=esc(T("Aucun incident pour ce filtre.","No incident for this filter."))+' <button type="button" class="shbtn" style="margin-left:8px" data-onclick="socIncFilter(\'all\',true)">'+esc(T("Tout afficher","Show all"))+'</button>';}
  else if(none)none.remove();
  document.querySelectorAll("#p-incidents .fchip").forEach(function(b){b.setAttribute("aria-pressed",b.getAttribute("data-f")===INCF?"true":"false");});
  var c=q1("#incCount");if(c)c.textContent=rows.length?(shown+" / "+rows.length):"";}
window.socIncFilter=function(f,clear){INCF=f;LS.set("soc_incf",f);if(clear){var qi=q1("#incQ");if(qi)qi.value="";}incFilter();};
document.querySelectorAll("#p-incidents .fchip").forEach(function(b){b.addEventListener("click",function(){socIncFilter(b.getAttribute("data-f"));});});
(function(){var qi=q1("#incQ");if(qi)qi.addEventListener("input",incFilter);})();
if(typeof renderCases==="function"){var _rc=renderCases;window.renderCases=function(list){
  try{(list||[]).forEach(function(x){if(x&&(!x.title||x.title==="None"))x.title=caseTitle(x);});}catch(e){}
  var r=_rc.apply(this,arguments);
  try{incFilter();var hot=(list||[]).filter(function(x){var s=sevClass(x.severity);return isOpen(x)&&(s==="critical"||s==="high");}).length;badges(hot);}catch(e){}
  if(PENDING_CASE)openCaseId(PENDING_CASE);return r;};}

/* ---------- états de chargement / d'erreur (SOAR, Exploitation) ---------- */
function skel(n,cls){var s="";for(var i=0;i<n;i++)s+='<span class="skel '+cls+'" aria-hidden="true"></span>';return s;}
function errBox(msg,retry){return '<div class="stateerr" role="alert"><b>'+esc(msg)+'</b><span>'+esc(NET.off?T("Hors ligne : les données n'ont pas pu être chargées.","Offline: data could not be loaded."):T("Les données n'ont pas pu être chargées.","Data could not be loaded."))+'</span><button type="button" class="shbtn" data-onclick="'+retry+'">'+esc(T("Réessayer","Retry"))+'</button></div>';}
window.socErrBox=errBox;
var SOAR_OK=false,OPS_OK=false;
window.loadSoar=function(){var a=q1("#sactive"),k=q1("#skpis");if(a&&!SOAR_OK){if(k)k.innerHTML=skel(4,"skkpi");a.innerHTML=skel(3,"skrow");}
  j("/soar").then(function(d){SOAR_OK=true;renderSoar(d);}).catch(function(e){if(e==="auth"){location.reload();return;}
    if(!SOAR_OK){if(k)k.innerHTML="";if(a)a.innerHTML=errBox(T("SOAR indisponible","SOAR unavailable"),"loadSoar()");}else toastNet();});};
window.loadOps=function(){var it=q1("#oitems"),st=q1("#ostatus");if(it&&!OPS_OK){if(st)st.innerHTML=skel(1,"skrow");it.innerHTML=skel(6,"skkpi");}
  j("/siem-ops").then(function(d){OPS_OK=true;renderOps(d);}).catch(function(e){if(e==="auth"){location.reload();return;}
    if(!OPS_OK){if(st)st.innerHTML="";if(it)it.innerHTML='<div class="card" style="grid-column:1/-1">'+errBox(T("Exploitation indisponible","Operations unavailable"),"loadOps()")+'</div>';}else toastNet();});};

/* ---------- thème : système / clair / sombre ---------- */
function themeMode(){var v=LS.get("soc_theme");return v==="light"||v==="dark"?v:"system";}
function metaTheme(){var m=q1("#mThemeColor");if(m)m.setAttribute("content",document.documentElement.getAttribute("data-theme")==="light"?"#f4f6fa":"#070a11");}
if(typeof window.socTheme==="function"){var _st=window.socTheme;window.socTheme=function(v){var r=_st.apply(this,arguments);metaTheme();return r;};}
function setThemeMode(m){if(m==="system"){LS.set("soc_theme",null);socTheme();}else socTheme(m);metaTheme();}
try{matchMedia("(prefers-color-scheme: light)").addEventListener("change",function(){if(themeMode()==="system"){socTheme();metaTheme();}});}catch(e){}
metaTheme();

/* ---------- service worker : installation, mises à jour, messages ---------- */
var SWREG=null,UPD_ASKED=false,SWV="",LASTSWCHK=Date.now();
function sendCfg(){try{var c=navigator.serviceWorker.controller||(SWREG&&SWREG.active);if(c)c.postMessage({type:"cfg",cfg:{offline:LS.get("soc_offline")!=="0"}});}catch(e){}}
function showUpd(w){var b=q1("#updbar");if(!b)return;b.querySelector(".ubt").textContent=T("Nouvelle version de la console disponible.","A new version of the console is available.");
  var g=q1("#updGo");g.textContent=T("Recharger","Reload");
  g.onclick=function(){UPD_ASKED=true;try{w.postMessage({type:"skip-waiting"});}catch(e){}setTimeout(function(){location.reload();},3000);};
  b.classList.add("on");}
function swInit(){if(!("serviceWorker" in navigator))return;
  navigator.serviceWorker.register("/soc/sw.js",{scope:"/soc/",updateViaCache:"none"}).then(function(reg){SWREG=reg;
    if(reg.waiting&&navigator.serviceWorker.controller)showUpd(reg.waiting);
    reg.addEventListener("updatefound",function(){var w=reg.installing;if(!w)return;w.addEventListener("statechange",function(){if(w.state==="installed"&&navigator.serviceWorker.controller)showUpd(w);});});
    sendCfg();
    try{var c=navigator.serviceWorker.controller;if(c)c.postMessage({type:"version"});}catch(e){}
  }).catch(function(e){try{console.warn("service worker",e);}catch(_){}});
  navigator.serviceWorker.addEventListener("controllerchange",function(){sendCfg();if(UPD_ASKED){UPD_ASKED=false;location.reload();}});
  navigator.serviceWorker.addEventListener("message",function(e){var d=e.data||{};if(d.type==="open"&&d.url)openUrl(d.url);if(d.type==="version")SWV=d.version||"";});}
document.addEventListener("visibilitychange",function(){if(document.hidden)return;
  try{if(appOn()&&!RELOADING&&Date.now()-UPD_AT>45000)refreshNow();}catch(e){}
  if(SWREG&&Date.now()-LASTSWCHK>1800000){LASTSWCHK=Date.now();SWREG.update().catch(function(){});}});

/* ---------- installation de l'application ---------- */
var DEFER=null;
function isStandalone(){try{return matchMedia("(display-mode: standalone)").matches||navigator.standalone===true;}catch(e){return false;}}
function isIOS(){return /iphone|ipad|ipod/i.test(navigator.userAgent)||(navigator.platform==="MacIntel"&&navigator.maxTouchPoints>1);}
window.addEventListener("beforeinstallprompt",function(e){e.preventDefault();DEFER=e;var d=q1("#appBtn .appdot");if(d)d.hidden=false;if(q1("#sheet.on"))renderSheet();});
window.addEventListener("appinstalled",function(){DEFER=null;var d=q1("#appBtn .appdot");if(d)d.hidden=true;toastOk(T("Application installée : retrouvez « OMNI SOC » sur l'écran d'accueil.","App installed: find “OMNI SOC” on your home screen."));});
window.socInstall=function(){if(!DEFER)return;DEFER.prompt();DEFER.userChoice.then(function(){DEFER=null;var d=q1("#appBtn .appdot");if(d)d.hidden=true;renderSheet();});};

/* ---------- notifications push ---------- */
function pushSupported(){return "serviceWorker" in navigator&&"PushManager" in window&&"Notification" in window;}
function b64u(s){s=String(s||"");var raw=atob((s+"=".repeat((4-s.length%4)%4)).replace(/-/g,"+").replace(/_/g,"/"));var a=new Uint8Array(raw.length);for(var i=0;i<raw.length;i++)a[i]=raw.charCodeAt(i);return a;}
function sameKey(sub,key){try{var k=sub.options&&sub.options.applicationServerKey;if(!k)return true;var a=new Uint8Array(k);if(a.length!==key.length)return false;for(var i=0;i<a.length;i++)if(a[i]!==key[i])return false;return true;}catch(e){return true;}}
function postJ(u,body){return fetch(API+u,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
  .then(function(r){if(r.status===401)throw "auth";return r.json().catch(function(){return {ok:false,error:"HTTP "+r.status};});});}
var PUSH={s:"?",sub:null};
async function pushRefresh(){
  if(!pushSupported()){PUSH={s:isIOS()&&!isStandalone()?"ios":"unsupported",sub:null};return PUSH;}
  if(Notification.permission==="denied"){PUSH={s:"denied",sub:null};return PUSH;}
  var reg=SWREG||await navigator.serviceWorker.getRegistration("/soc/");
  if(!reg){PUSH={s:"nosw",sub:null};return PUSH;}
  var sub=await reg.pushManager.getSubscription();PUSH={s:sub&&Notification.permission==="granted"?"on":"off",sub:sub};return PUSH;}
async function pushSubscribe(reg){var k=await j("/vapid");var key=b64u(k.publicKey);var sub=await reg.pushManager.getSubscription();
  if(sub&&!sameKey(sub,key)){await sub.unsubscribe();sub=null;}
  if(!sub)sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:key});
  var r=await postJ("/subscribe",{subscription:sub});if(!r||!r.ok){try{await sub.unsubscribe();}catch(_){}throw (r&&r.error)||"subscribe";}return sub;}
window.socPushOn=async function(){try{
    if(!pushSupported()){toastWarn(isIOS()?T("Sur iPhone : installez d'abord l'application (Partager → Sur l'écran d'accueil), puis activez les notifications depuis l'application.","On iPhone: install the app first (Share → Add to Home Screen), then enable notifications from the app."):T("Ce navigateur ne gère pas les notifications push.","This browser does not support push notifications."));return;}
    var perm=await Notification.requestPermission();
    if(perm!=="granted"){toastWarn(T("Notifications refusées : autorisez-les dans les réglages du navigateur pour ce site.","Notifications denied: allow them in the browser settings for this site."));renderSheet();return;}
    await pushSubscribe(await navigator.serviceWorker.ready);
    toastOk(T("Notifications activées sur cet appareil.","Notifications enabled on this device."));
  }catch(e){if(e==="auth"){location.reload();return;}toastErr(T("Activation impossible : ","Could not enable: ")+(e&&e.message?e.message:String(e)));}
  renderSheet();};
window.socPushOff=async function(){try{var st=await pushRefresh();if(st.sub){var ep=st.sub.endpoint;await st.sub.unsubscribe();await postJ("/unsubscribe",{endpoint:ep}).catch(function(){});}
    toastInfo(T("Notifications désactivées sur cet appareil.","Notifications disabled on this device."));}catch(e){toastErr(String(e));}renderSheet();};
window.socPushTest=async function(){try{var st=await pushRefresh();if(!st.sub){toastWarn(T("Activez d'abord les notifications.","Enable notifications first."));return;}
    var r=await postJ("/push-test",{endpoint:st.sub.endpoint});
    if(r&&r.ok)toastOk(T("Test envoyé : la notification doit arriver dans quelques secondes.","Test sent: the notification should arrive within seconds."));
    else toastWarn((r&&r.error)||T("Échec de l'envoi.","Sending failed."));}catch(e){if(e==="auth"){location.reload();return;}toastErr(T("Échec du test.","Test failed."));}};
async function pushResync(){try{if(!pushSupported()||Notification.permission!=="granted")return;var reg=await navigator.serviceWorker.ready;var sub=await reg.pushManager.getSubscription();if(sub)await pushSubscribe(reg);}catch(e){}}

/* ---------- menu (feuille) : pages, réglages, application ---------- */
var SHEET_OPENER=null;
function seg(name,opts,cur){return '<span class="seg" role="group" aria-label="'+esc(name)+'">'+opts.map(function(o){return '<button type="button" aria-pressed="'+(o[0]===cur?"true":"false")+'" data-onclick="'+o[2]+'">'+esc(o[1])+'</button>';}).join("")+'</span>';}
async function renderSheet(){var body=q1("#shBody");if(!body)return;
  var p=curPage(),html="";
  var tt=q1("#shTitle");if(tt)tt.textContent=T("Menu","Menu");
  // pages (mobile)
  html+='<div class="shpages"><div class="shsec">'+esc(T("Pages","Pages"))+'</div><div class="shgrid">';
  document.querySelectorAll("#nav a[data-p]").forEach(function(a){var pg=a.getAttribute("data-p");var ic=a.querySelector(".ic");var lab=a.querySelector("span:not(.ic):not(.navbadge)");
    html+='<button type="button" data-onclick="goNav(\''+pg+'\')"'+(pg===p?' aria-current="page"':'')+'>'+(ic?ic.innerHTML:"")+'<span>'+esc(lab?lab.textContent:pg)+'</span></button>';});
  html+='</div></div>';
  // notifications
  await pushRefresh().catch(function(){});
  var ps=PUSH.s,pl={on:T("Activées sur cet appareil","Enabled on this device"),off:T("Désactivées","Disabled"),denied:T("Bloquées dans le navigateur","Blocked by the browser"),
    unsupported:T("Non prises en charge par ce navigateur","Not supported by this browser"),ios:T("iPhone : installez d'abord l'application","iPhone: install the app first"),nosw:T("Service hors ligne non actif","Offline service not active"),"?":"…"}[ps]||ps;
  html+='<div class="shsec">'+esc(T("Alertes sur cet appareil","Alerts on this device"))+'</div>';
  html+='<div class="shrow"><span class="lb">'+esc(T("Notifications push","Push notifications"))+'<small>'+esc(pl)+'</small></span>';
  if(ps==="on")html+='<button type="button" class="shbtn" data-onclick="socPushTest()">'+esc(T("Envoyer un test","Send a test"))+'</button><button type="button" class="shbtn" data-onclick="socPushOff()">'+esc(T("Désactiver","Disable"))+'</button>';
  else if(ps==="off"||ps==="nosw"||ps==="?")html+='<button type="button" class="shbtn pri" data-onclick="socPushOn()">'+esc(T("Activer","Enable"))+'</button>';
  html+='</div>';
  // application
  var inst=isStandalone()?T("Installée — vous l'utilisez","Installed — in use"):DEFER?T("Installable sur cet appareil","Can be installed on this device"):isIOS()?T("Safari : Partager → Sur l'écran d'accueil","Safari: Share → Add to Home Screen"):T("Menu du navigateur → Installer l'application","Browser menu → Install app");
  html+='<div class="shrow"><span class="lb">'+esc(T("Application","App"))+'<small>'+esc(inst)+'</small></span>'+(DEFER?'<button type="button" class="shbtn pri" data-onclick="socInstall()"><svg class="svi" aria-hidden="true"><use href="#i-download"></use></svg> '+esc(T("Installer","Install"))+'</button>':'')+'</div>';
  html+='<div class="shrow"><span class="lb">'+esc(T("Copie hors ligne","Offline copy"))+'<small>'+esc(T("Dernières données lisibles sans réseau (24 h max., effacées à la déconnexion)","Latest data readable offline (24 h max, erased at sign-out)"))+'</small></span>'
    +seg(T("Copie hors ligne","Offline copy"),[["1",T("Oui","On"),"socOffline('1')"],["0",T("Non","Off"),"socOffline('0')"]],LS.get("soc_offline")==="0"?"0":"1")+'</div>';
  // affichage
  html+='<div class="shsec">'+esc(T("Affichage","Display"))+'</div>';
  html+='<div class="shrow"><span class="lb">'+esc(T("Thème","Theme"))+'</span>'+seg(T("Thème","Theme"),[["system",T("Système","System"),"socThemeMode('system')"],["light",T("Clair","Light"),"socThemeMode('light')"],["dark",T("Sombre","Dark"),"socThemeMode('dark')"]],themeMode())+'</div>';
  html+='<div class="shrow"><span class="lb">'+esc(T("Langue","Language"))+'</span>'+seg(T("Langue","Language"),[["fr","FR","setLang('fr')"],["en","EN","setLang('en')"]],EN()?"en":"fr")+'</div>';
  var dens="comfortable";try{dens=_densRead();}catch(e){}
  html+='<div class="shrow"><span class="lb">'+esc(T("Densité","Density"))+'</span>'+seg(T("Densité","Density"),[["comfortable",T("Confort","Comfort"),"socDens('comfortable')"],["compact",T("Compacte","Compact"),"socDens('compact')"]],dens)+'</div>';
  var cad="60000";try{cad=getCadence();}catch(e){}
  html+='<div class="shrow"><span class="lb">'+esc(T("Rafraîchissement","Refresh"))+'</span>'+seg(T("Rafraîchissement","Refresh"),[["30000","30 s","socCad('30000')"],["60000","60 s","socCad('60000')"],["0",T("Pause","Pause"),"socCad('0')"]],cad)+'</div>';
  // divers
  html+='<div class="shsec">'+esc(T("Session","Session"))+'</div><div class="shrow"><button type="button" class="shbtn" data-onclick="socCloseSheet();openHelp()">'+esc(T("Aide et raccourcis","Help & shortcuts"))+'</button><button type="button" class="shbtn" data-onclick="logout()">'+esc(T("Se déconnecter","Sign out"))+'</button></div>';
  html+='<div class="shfoot">OMNI SOC '+esc(V3)+(SWV?' · '+esc(SWV):'')+'</div>';
  body.innerHTML=html;}
window.socThemeMode=function(m){setThemeMode(m);renderSheet();};
window.socDens=function(m){try{applyDensity(m);}catch(e){}renderSheet();};
window.socCad=function(v){try{setCadence(v);}catch(e){}renderSheet();};
window.socOffline=function(v){LS.set("soc_offline",v==="0"?"0":null);if(v==="0")purgeData();sendCfg();renderSheet();};
window.socSheet=function(){var s=q1("#sheet");if(!s)return;SHEET_OPENER=document.activeElement;s.classList.add("on");s.setAttribute("aria-hidden","false");
  ["#appBtn","#bMore"].forEach(function(id){var b=q1(id);if(b)b.setAttribute("aria-expanded","true");});
  renderSheet().then(function(){var f=s.querySelector(".shbox button,.shbox [tabindex]");var box=s.querySelector(".shbox");try{(box||f).focus();}catch(e){}});};
window.socCloseSheet=function(){var s=q1("#sheet");if(!s||!s.classList.contains("on"))return;s.classList.remove("on");s.setAttribute("aria-hidden","true");
  ["#appBtn","#bMore"].forEach(function(id){var b=q1(id);if(b)b.setAttribute("aria-expanded","false");});
  var o=SHEET_OPENER;SHEET_OPENER=null;if(o&&o.focus&&document.contains(o)){try{o.focus();}catch(e){}}};
function socCloseSheet(){window.socCloseSheet();}
document.addEventListener("keydown",function(e){var s=q1("#sheet.on");if(!s)return;
  if(e.key==="Escape"){e.preventDefault();socCloseSheet();return;}
  if(e.key!=="Tab")return;var f=s.querySelectorAll(".shbox button:not([disabled]),.shbox a[href]");if(!f.length)return;
  var first=f[0],last=f[f.length-1],a=document.activeElement;
  if(e.shiftKey&&(a===first||!s.contains(a))){e.preventDefault();last.focus();}else if(!e.shiftKey&&a===last){e.preventDefault();first.focus();}},true);

/* ---------- démarrage ---------- */
function afterStart(){if(STARTED)return;STARTED=true;var o=hashParams();
  if(o.p)navTo(o.p);
  if(o["case"])PENDING_CASE=o["case"];
  syncNav(curPage());bnavI18n();metaTheme();
  if(o.e||o["case"])setTimeout(function(){var h="#p="+curPage();try{history.replaceState(null,"",h);}catch(e){}LASTH=h;},8000);
  else LASTH=location.hash;
  setTimeout(pushResync,4000);}
if(typeof start==="function"){var _sa=start;window.start=function(){var r=_sa.apply(this,arguments);try{afterStart();}catch(e){}return r;};}
if(appOn())afterStart();
syncNav(curPage());bnavI18n();
swInit();
})();
