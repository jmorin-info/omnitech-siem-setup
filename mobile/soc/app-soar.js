/* OMNITECH-SOC-20261111 : pages SOAR et Exploitation, bande « À traiter », liens Graylog, thème clair */
(function(){
const SEVC={ok:"var(--grn)",warn:"var(--amb)",crit:"var(--red)"};
const SEVL={ok:"Tout va bien",warn:"À surveiller",crit:"Critique"};
const fmtAge=s=>{if(s==null)return"?";if(s<120)return s+" s";if(s<7200)return Math.round(s/60)+" min";return Math.round(s/3600)+" h";};
const fmtUntil=e=>new Date(e*1000).toLocaleString("fr",{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit"});
const d16=v=>String(v||"").slice(0,16).replace("T"," ");
window.glSearch=function(q,sec){return "/search?q="+encodeURIComponent(q||"*")+"&rangetype=relative&relative="+(sec||604800);};
window.caseQuery=function(x){const t=String((x&&x.entities)||"").split(/[,;\s]+/).map(v=>v.replace(/^[a-z_]+:/i,"").replace(/"/g,"")).filter(v=>v&&v.length>2).slice(0,4);
  return t.length?t.map(v=>'"'+v+'"').join(" OR "):String((x&&(x.rule||x.title))||"*");};
let SOARD={};
window.loadSoar=function(){j("/soar").then(renderSoar).catch(e=>{if(e==="auth")location.reload();else toastNet();});};
window.renderSoar=function(d){SOARD=d||{};const a=SOARD.active||[],ex=SOARD.exclusions||{},st=ex.dynamic_stats||{};
  $("#skpis").innerHTML=[
    [a.length?"amb":"grn","IP bloquées",a.length,"Bordeaux + Ivry"],
    [(SOARD.feed_age_s!=null&&SOARD.feed_age_s<3900)?"cy":"red","Liste publiée",fmtAge(SOARD.feed_age_s),"âge du fichier lu par les FortiGate (réécrit à :30 chaque heure et à chaque blocage)"],
    ["vio","Exclusions automatiques",((st.vpn||0)+(st.m365||0)).toLocaleString("fr"),"IP légitimes (VPN, M365) sur "+(ex.dynamic_days||90)+" j"],
    ["cy","Exclusions fixes",ex.static||0,"sites, partenaires, prestataires"]
  ].map(([c,l,v,s])=>`<div class="kpi ${c}"><div class="lab">${l}</div><div class="val mono">${esc(String(v))}</div><div class="sub">${s}</div></div>`).join("");
  const adm=!!SOARD.is_admin;
  $("#sactive").innerHTML=a.length?a.map((x,i)=>`<div class="inc sev-high"><div class="top"><span class="ttl mono">${esc(x.ip)}</span>${x.pays?`<span class="pchip">${esc(x.pays)}</span>`:""}<span class="ts" style="margin-left:auto">jusqu'au ${fmtUntil(x.until)} · reste ${esc(String(x.remaining_h))} h</span>${adm?`<button class="iconbtn" type="button" style="margin-left:10px" data-onclick="event.stopPropagation();socUnblockForm(${i})" aria-expanded="false">Débloquer</button>`:""}</div><div class="meta">${esc(x.detection||x.motif||"détection SOAR")}${x.hits?" · "+esc(String(x.hits))+" occurrences":""}${x.since?" · depuis "+esc(d16(x.since)):""} · <a href="${glSearch('"'+x.ip+'"')}" target="_blank" rel="noopener">voir dans Graylog ↗</a></div><div id="sub${i}"></div></div>`).join(""):'<div class="empty">Aucune IP bloquée actuellement ✅</div>';
  const rq=SOARD.requests||[];
  $("#sreq").innerHTML=rq.length?rq.map(r=>`<div class="inc"><div class="top"><span class="ttl mono">${esc(r.ip||"")}</span><span class="pchip">${esc(r.status||"")}</span><span class="ts" style="margin-left:auto">${esc(d16(r.t))} · ${esc(r.user||"")}</span></div>${r.resultat?`<div class="meta">${esc(r.resultat)}</div>`:""}</div>`).join(""):'<div class="empty">Aucune demande depuis la console</div>';
  const hi=SOARD.history||[];
  $("#shist").innerHTML=hi.length?hi.map(e=>`<div class="inc"><div class="top"><span class="chip">${esc(String(e.action||"").replace(/_/g," "))}</span><span class="ttl mono">${esc(e.ip||"")}</span><span class="ts" style="margin-left:auto">${esc(d16(e.t))}</span></div><div class="meta">${esc(e.motif||e.detection||"")}${e.par?" · par "+esc(e.par):""}</div></div>`).join(""):'<div class="empty">—</div>';
};
window.socUnblockForm=function(i){const x=(SOARD.active||[])[i];if(!x)return;const el=$("#sub"+i);if(!el)return;if(el.innerHTML){el.innerHTML="";return;}
  el.innerHTML=`<div class="socform"><label><input type="checkbox" id="sx${i}"> Ne plus jamais bloquer cette IP</label><input class="motif" id="sm${i}" maxlength="80" placeholder="Motif (obligatoire pour une exclusion), ex. : domicile d'un collaborateur" aria-label="Motif de l'exclusion"><button class="iconbtn" type="button" data-onclick="socUnblock(${i})">Confirmer le déblocage de ${esc(x.ip)}</button></div>`;
  const m=$("#sm"+i);if(m)m.focus();};
window.socUnblock=function(i){const x=(SOARD.active||[])[i];if(!x)return;const ex=!!($("#sx"+i)&&$("#sx"+i).checked),m=(($("#sm"+i)||{}).value||"").trim();
  if(ex&&m.length<4){toastWarn("Indiquez un motif pour l'exclusion définitive.");return;}
  fetch(API+"/soar/unblock",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({ip:x.ip,exclure:ex,motif:m})})
    .then(r=>{if(r.status===401)throw"auth";return r.json();})
    .then(r=>{if(r.ok){toastOk(r.message||"Demande enregistrée");loadSoar();setTimeout(loadSoar,15000);}else toastErr(r.error||"Refusé");})
    .catch(e=>{if(e==="auth")location.reload();else toastNet();});};
window.loadOps=function(){j("/siem-ops").then(renderOps).catch(()=>toastNet());};
window.renderOps=function(d){d=d||{};const it=d.items||[];const c=SEVC[d.status]||"var(--mut)";const nb=it.filter(x=>x.status!=="ok").length;
  $("#ostatus").innerHTML=`<div class="todo" style="border-left-color:${c}"><b style="color:${c}">${SEVL[d.status]||"?"}</b><span>${nb?nb+" point(s) à regarder":"aucun point à regarder"} sur ${it.length} · noyau ${esc(d.kernel||"")} · calculé à ${esc(String(d.generated||"").slice(11,16))}</span></div>`;
  $("#oitems").innerHTML=it.map(x=>`<div class="kpi" style="border-left:4px solid ${SEVC[x.status]||"var(--bd)"}"><div class="lab">${esc(x.label)}</div><div class="val mono" style="font-size:18px">${esc(x.value)}</div><div class="sub">${esc(x.detail||"")}</div></div>`).join("");
  $("#overs").innerHTML=(d.versions||[]).map(v=>`<span class="pchip mono">${esc(v)}</span>`).join("")||'<div class="empty">—</div>';};
window.loadTodo=function(){Promise.all([j("/siem-ops").catch(()=>null),j("/soar").catch(()=>null),j("/health").catch(()=>null),j("/cases").catch(()=>null)]).then(([o,s,h,c])=>{
  const L=[];const cs=(c&&c.cases)||[];
  const open=x=>x.status!=="closed"&&x.status!=="resolved";
  const cr=cs.filter(x=>x.severity==="critical"&&open(x)).length,hi=cs.filter(x=>x.severity==="high"&&open(x)).length,nw=cs.filter(x=>x.status==="new").length;
  if(cr)L.push(["crit",cr+" incident(s) critique(s) ouvert(s)","incidents"]);
  if(hi)L.push(["warn",hi+" incident(s) élevé(s) ouvert(s)","incidents"]);
  if(nw&&nw>=10)L.push(["warn",nw+" incidents jamais qualifiés","incidents"]);
  const dk=(h&&h.dark_hosts)||[];if(dk.length)L.push(["warn",dk.length+" hôte(s) silencieux","health"]);
  const rb=(h&&h.robots)||{};if(rb.health_fail>0)L.push(["warn",rb.health_fail+" robot(s) SIEM en panne","health"]);
  ((o&&o.items)||[]).filter(x=>x.status!=="ok").forEach(x=>L.push([x.status,x.label+" : "+x.value,"ops"]));
  if(s&&s.count)L.push(["info",s.count+" IP bloquée(s) par le SOAR","soar"]);
  const el=$("#todo");if(!el)return;
  el.innerHTML=`<div class="todo"><b>À traiter</b>`+(L.length?L.map(([v,t,p])=>`<span class="tdi tdi-${v}" role="button" tabindex="0" data-onclick="goNav('${p}')" data-onkeydown="socNavKey(event,'${p}')">${esc(t)}</span>`).join(""):`<span class="tdi tdi-ok">Rien d'urgent ✅</span>`)+`</div>`;});};
window.socTheme=function(v){if(v){try{localStorage.setItem("soc_theme",v)}catch(e){}}
  let th=v;if(!th){try{th=localStorage.getItem("soc_theme")}catch(e){}}th=th||((window.matchMedia&&matchMedia("(prefers-color-scheme: light)").matches)?"light":"dark");
  document.documentElement.setAttribute("data-theme",th);const b=document.getElementById("themeBtn");if(b)b.textContent=th==="light"?"☾ Sombre":"☀ Clair";};
socTheme();
})();
