const API="/m/api", $=s=>document.querySelector(s);
function ic(n){return '<svg class="svi" aria-hidden="true" focusable="false"><use href="#i-'+n+'"></use></svg>';}
const j=(u,o)=>fetch(API+u,{credentials:"same-origin",...o}).then(r=>{if(r.status===401)throw"auth";return r.json()});
const esc=s=>(s==null?"":""+s).replace(/[<>&]/g,c=>({"<":"&lt;",">":"&gt;","&":"&amp;"}[c]));
const nice=s=>esc((s||"").toString().replace(/_/g," ").replace(/\b\w/g,c=>c.toUpperCase()));
const ago=t=>{if(!t)return"";let d=(Date.now()-new Date((""+t).replace(" ","T").replace(/(Z|[+-]\d\d:?\d\d)?$/,"Z")).getTime())/1000;
  return d<60?(LANG==="en"?"just now":"à l'instant"):d<3600?(d/60|0)+" min":d<86400?(d/3600|0)+" h":(d/86400|0)+(LANG==="en"?" d":" j")};
const PAL=["#22d3ee","#a78bfa","#fb3b53","#f5a623","#34d399","#3b82f6","#e879f9","#2dd4bf"];
const TACCOL={"Initial Access":"#fb3b53","Execution":"#f97316","Persistence":"#f5a623","Privilege Escalation":"#eab308","Defense Evasion":"#a78bfa","Credential Access":"#ec4899","Discovery":"#22d3ee","Lateral Movement":"#3b82f6","Collection":"#14b8a6","Command and Control":"#8b5cf6","Exfiltration":"#f43f5e","Impact":"#ef4444"};

// --- i18n (FR/EN) ---------------------------------------------------------
let LANG=localStorage.getItem("soc_lang")||"fr";
const I18N={
 fr:{
  nav_overview:"Vue d'ensemble",nav_incidents:"Incidents",nav_detections:"Détections",nav_attack:"ATT&CK",nav_graph:"Graphe d'attaque",nav_twin:"Jumeau d'attaque",twin_loading:"Chargement du jumeau d'attaque…",nav_ems:"Endpoint (EMS)",ems_loading:"Chargement de la télémétrie endpoint…",nav_network:"Réseau & Infra",net_loading:"Chargement de l'activité réseau & infra…",nav_deploy:"Déploiement",dep_loading:"Chargement du centre de déploiement…",nav_globe:"Carte mondiale",globe_threat:"menace",globe_traffic:"trafic",globe_topc:"Top pays · menace",globe_win:"3 h",globe_live:"Flux en direct",nav_leaks:"Fuites & Dark Web",nav_health:"Santé & Collecte",nav_report:"Rapport",nav_playbooks:"Playbooks",pb_title:"Playbooks de réponse",pb_sub:"guide d'action par détection, regroupé par tactique ATT&CK",pb_search:"Rechercher une détection, technique, mot-clé…",pb_none:"Aucune détection ne correspond.",nav_entities:"Entités",ent_pgt:"Recherche d'entités",ent_pgs:"comptes & machines — dossier 360° unifié",ent_ph:"Compte AD, e-mail, ou nom de machine…",ent_topu:"Comptes les plus actifs",ent_topm:"Machines les plus actives",ent_res:"Résultats",ent_nores:"Aucune entité trouvée.",tl_title:"Chronologie unifiée",tl_sub:"— détections + échecs d'authentification, par date",tl_ok:"réussi",tl_fail:"échoué",maint_title:"Maintenance requise",watch_on:"Surveillée",watch_off:"Surveiller",watch_hint:"Ajouter/retirer de la liste de surveillance",watch_added:"Ajoutée à la surveillance",watch_removed:"Retirée de la surveillance",watch_section:"Sous surveillance",
  cluster_ok:"Cluster opérationnel",dens_comfort:"Confort",dens_compact:"Compact",
  al_search:"Recherche et navigation (Ctrl ou Cmd + K)",al_refresh:"Rafraîchir les données",al_density:"Basculer la densité d'affichage",al_help:"Ouvrir l'aide et les raccourcis clavier",al_logout:"Se déconnecter",al_lang:"Changer la langue (FR/EN)",
  t_search:"Recherche (Ctrl/Cmd+K)",t_refresh:"Rafraîchir maintenant",t_help:"Aide et raccourcis (touche ?)",t_logout:"Se déconnecter",t_lang:"Langue : Français — cliquer pour English",
  login_account:"Compte AD",login_password:"Mot de passe",login_signin:"Se connecter",
  card_sentinel:"OMNI Sentinel — Posture proactive",tag_sentinel:"jumeau d'attaque · cliquer",
  card_det24:"Détections (24 h)",tag_perhour:"par heure",card_tactics:"Tactiques ATT&CK",tag_7d:"7 j",card_topdet:"Top détections",card_sources:"Sources",
  card_mlanom:"Anomalies ML",tag_mlanom:"oms-ml · IsolationForest · cliquer pour la fiche",card_uebarisk:"Risque UEBA",tag_uebarisk:"score comportemental · 24 h",
  card_topent:"Top entités à risque",tag_topent:"7 j · risque fusionné · cliquer",card_live:"Flux temps réel",card_geo:"Origines géographiques des sources externes",tag_geo:"7 j · FortiGate GeoIP",
  card_incidents:"Incidents corrélés (oms-xdr)",card_matrix:"Matrice MITRE ATT&CK",tag_matrix:"couverture × activité (7 j)",card_graph:"Graphe d'attaque",tag_graph:"entités ↔ techniques ATT&CK (7 j)",
  card_leaksrc:"Sources de fuite surveillées",tag_leaksrc:"30 j · RansomLook / HIBP / Dehashed / GitHub",card_collect:"Sources de collecte (24 h)",tag_collect:"volume · dernier événement",card_dark:"Hôtes silencieux (go‑dark)",tag_dark:"muets > 26 h · à vérifier",card_posture:"Rapport de posture",
  ph_detsearch:"🔎 Rechercher (tag, entité, technique, message…)",btn_reset:"Réinitialiser",btn_csv:"⤓ CSV",ph_gsearch:"🔎 Centrer une entité…",btn_print:"Imprimer / PDF",ph_palette:"Rechercher / naviguer…  (pages, entités)",
  help_title:"Aide & raccourcis",help_sub:"Console SOC — OMNITECH SECURITY",
  empty_waiting:"En attente d'événements…",empty_ml:"Aucune anomalie ML récente",empty_ueba:"Aucun score UEBA récent",empty_geo:"Aucune donnée géo",empty_event:"Aucun événement",
  ent_tactics:"Tactiques",ent_techniques:"Techniques ATT&CK",ent_events:"Événements récents",ent_detn:"détections (7 j)",load_more:"Charger plus",events_shown:"événements affichés",id_unified:"Identité unifiée — {n} comptes liés (vue agrégée) :",
  inv_title:"Investigation — provenance & cartographie",inv_authmap:"Cartographie des sources d'authentification",inv_timeline:"Chronologie — réussis / échecs",inv_ips:"IP sources",inv_ips_hint:"— une réussite depuis l'étranger = à investiguer",inv_codes:"Codes de statut",inv_prov:"Provenance des détections",inv_presence:"Présence par source",inv_analyzing:"Analyse en cours…",inv_none:"Aucune donnée d'investigation pour cette entité",inv_winauth:"Authentification Windows (logons 4624/4625)",inv_logontypes:"Types de logon",inv_failreasons:"Motifs d'échec",k_logons:"logons",pal_evts:"évts",
  rep_title:"OMNITECH SECURITY — Rapport de posture SOC",rep_gen:"Généré le",rep_plat:"plateforme SIEM/XDR (Graylog + oms-xdr)",rep_k_inc:"Incidents critiques (7 j)",rep_k_det:"Détections (24 h)",rep_k_tech:"Techniques ATT&CK",rep_k_evt:"Événements (24 h)",rep_cov:"Couverture MITRE ATT&CK",rep_cov1:"techniques sur",rep_cov2:"tactiques couvertes. État du cluster de collecte :",rep_posture:"Posture opérationnelle",rep_robots:"Auto-supervision des robots d'analyse :",rep_oper:"opérationnels",rep_down:"en panne",rep_collect:"Couverture de collecte :",rep_sil1:"hôte(s) silencieux sur",rep_sil2:"attendus",rep_silh:"Hôtes muets :",rep_risk:"Entités à risque — scoring ML & UEBA",rep_mlanom:"Anomalies ML (IsolationForest)",rep_uebar:"Risque comportemental UEBA",rep_h_ent:"Entité",rep_h_score:"Score",rep_h_reason:"Motif principal",rep_h_factor:"Facteur",rep_topdet:"Top détections (7 jours)",rep_h_det:"Détection",rep_h_vol:"Volume",rep_recinc:"Incidents corrélés récents",rep_h_sev:"Sévérité",rep_h_title:"Titre",rep_noinc:"Aucun incident corrélé",rep_collsrc:"Sources de collecte (24 h)",rep_h_src:"Source",rep_foot:"Document généré automatiquement — démarche d'amélioration continue (ISO/IEC 27001:2022, clause 10). Preuve datée et reproductible.",leak_none:"Aucune source active (RansomLook tourne ; HIBP/Dehashed en attente de clés)",esc_ml:"Score ML",esc_ueba:"Score UEBA",risk_fused:"Risque fusionné · ML + UEBA + détections",risk_det:"Détections",risk_corrob:"signaux corroborés",risk_critical:"Critique",risk_high:"Élevé",risk_moderate:"Modéré",risk_low:"Faible",risk_minimal:"Minimal",g_title:"Guide d'action",g_what:"Ce que c'est",g_check:"À vérifier",g_remed:"Remédiation",g_correct:"Correction durable",g_none:"Pas de guide pour cette détection.",g_hint:"cliquer pour le guide d'action",g_show:"Guide d'action ▸",empty_det:"Aucune détection",
  k_attempts:"tentatives",k_success:"réussies",k_fail:"échecs",k_countries:"pays",k_ips:"IP sources",ch_ok:"Réussis",ch_ko:"Échecs",succ_suffix:"réussis",none_suffix:"0 réussi",
  case_status:"Statut du cas mis à jour.",case_disp:"Disposition enregistrée — le modèle de réduction des faux positifs s'ajustera.",case_assign:"Cas assigné.",case_note:"Note d'investigation ajoutée.",case_def:"Cas mis à jour."
 },
 en:{
  nav_overview:"Overview",nav_incidents:"Incidents",nav_detections:"Detections",nav_attack:"ATT&CK",nav_graph:"Attack graph",nav_twin:"Attack twin",twin_loading:"Loading the attack twin…",nav_ems:"Endpoint (EMS)",ems_loading:"Loading endpoint telemetry…",nav_network:"Network & Infra",net_loading:"Loading network & infra activity…",nav_deploy:"Deployment",dep_loading:"Loading the deployment center…",nav_globe:"World map",globe_threat:"threat",globe_traffic:"traffic",globe_topc:"Top countries · threats",globe_win:"3 h",globe_live:"Live flows",nav_leaks:"Leaks & Dark Web",nav_health:"Health & Collection",nav_report:"Report",nav_playbooks:"Playbooks",pb_title:"Response playbooks",pb_sub:"action guide per detection, grouped by ATT&CK tactic",pb_search:"Search a detection, technique, keyword…",pb_none:"No matching detection.",nav_entities:"Entities",ent_pgt:"Entity search",ent_pgs:"accounts & machines — unified 360° dossier",ent_ph:"AD account, email, or machine name…",ent_topu:"Most active accounts",ent_topm:"Most active machines",ent_res:"Results",ent_nores:"No entity found.",tl_title:"Unified timeline",tl_sub:"— detections + auth failures, by date",tl_ok:"success",tl_fail:"failed",maint_title:"Maintenance required",watch_on:"Watched",watch_off:"Watch",watch_hint:"Add/remove from watchlist",watch_added:"Added to watchlist",watch_removed:"Removed from watchlist",watch_section:"Watchlist",
  cluster_ok:"Cluster operational",dens_comfort:"Comfort",dens_compact:"Compact",
  al_search:"Search and navigation (Ctrl or Cmd + K)",al_refresh:"Refresh data",al_density:"Toggle display density",al_help:"Open help and keyboard shortcuts",al_logout:"Sign out",al_lang:"Change language (FR/EN)",
  t_search:"Search (Ctrl/Cmd+K)",t_refresh:"Refresh now",t_help:"Help and shortcuts (press ?)",t_logout:"Sign out",t_lang:"Language: English — click for Français",
  login_account:"AD account",login_password:"Password",login_signin:"Sign in",
  card_sentinel:"OMNI Sentinel — Proactive posture",tag_sentinel:"attack twin · click",
  card_det24:"Detections (24h)",tag_perhour:"per hour",card_tactics:"ATT&CK tactics",tag_7d:"7d",card_topdet:"Top detections",card_sources:"Sources",
  card_mlanom:"ML anomalies",tag_mlanom:"oms-ml · IsolationForest · click for details",card_uebarisk:"UEBA risk",tag_uebarisk:"behavioral score · 24h",
  card_topent:"Top risk entities",tag_topent:"7d · fused risk · click",card_live:"Live feed",card_geo:"External source geography",tag_geo:"7d · FortiGate GeoIP",
  card_incidents:"Correlated incidents (oms-xdr)",card_matrix:"MITRE ATT&CK matrix",tag_matrix:"coverage × activity (7d)",card_graph:"Attack graph",tag_graph:"entities ↔ ATT&CK techniques (7d)",
  card_leaksrc:"Monitored leak sources",tag_leaksrc:"30d · RansomLook / HIBP / Dehashed / GitHub",card_collect:"Collection sources (24h)",tag_collect:"volume · last event",card_dark:"Silent hosts (go‑dark)",tag_dark:"silent > 26h · to check",card_posture:"Posture report",
  ph_detsearch:"🔎 Search (tag, entity, technique, message…)",btn_reset:"Reset",btn_csv:"⤓ CSV",ph_gsearch:"🔎 Focus an entity…",btn_print:"Print / PDF",ph_palette:"Search / navigate…  (pages, entities)",
  help_title:"Help & shortcuts",help_sub:"SOC console — OMNITECH SECURITY",
  empty_waiting:"Waiting for events…",empty_ml:"No recent ML anomaly",empty_ueba:"No recent UEBA score",empty_geo:"No geo data",empty_event:"No event",
  ent_tactics:"Tactics",ent_techniques:"ATT&CK techniques",ent_events:"Recent events",ent_detn:"detections (7d)",load_more:"Load more",events_shown:"events shown",id_unified:"Unified identity — {n} linked accounts (aggregated view):",
  inv_title:"Investigation — provenance & map",inv_authmap:"Authentication source map",inv_timeline:"Timeline — success / failure",inv_ips:"Source IPs",inv_ips_hint:"— a success from abroad = investigate",inv_codes:"Status codes",inv_prov:"Detection provenance",inv_presence:"Presence by source",inv_analyzing:"Analyzing…",inv_none:"No investigation data for this entity",inv_winauth:"Windows authentication (4624/4625 logons)",inv_logontypes:"Logon types",inv_failreasons:"Failure reasons",k_logons:"logons",pal_evts:"events",
  rep_title:"OMNITECH SECURITY — SOC Posture Report",rep_gen:"Generated on",rep_plat:"SIEM/XDR platform (Graylog + oms-xdr)",rep_k_inc:"Critical incidents (7d)",rep_k_det:"Detections (24h)",rep_k_tech:"ATT&CK techniques",rep_k_evt:"Events (24h)",rep_cov:"MITRE ATT&CK coverage",rep_cov1:"techniques across",rep_cov2:"tactics covered. Collection cluster state:",rep_posture:"Operational posture",rep_robots:"Analysis-robot self-monitoring:",rep_oper:"operational",rep_down:"down",rep_collect:"Collection coverage:",rep_sil1:"silent host(s) of",rep_sil2:"expected",rep_silh:"Silent hosts:",rep_risk:"At-risk entities — ML & UEBA scoring",rep_mlanom:"ML anomalies (IsolationForest)",rep_uebar:"UEBA behavioral risk",rep_h_ent:"Entity",rep_h_score:"Score",rep_h_reason:"Main reason",rep_h_factor:"Factor",rep_topdet:"Top detections (7 days)",rep_h_det:"Detection",rep_h_vol:"Volume",rep_recinc:"Recent correlated incidents",rep_h_sev:"Severity",rep_h_title:"Title",rep_noinc:"No correlated incidents",rep_collsrc:"Collection sources (24h)",rep_h_src:"Source",rep_foot:"Automatically generated document — continual improvement (ISO/IEC 27001:2022, clause 10). Dated, reproducible evidence.",leak_none:"No active source (RansomLook running; HIBP/Dehashed awaiting keys)",esc_ml:"ML score",esc_ueba:"UEBA score",risk_fused:"Fused risk · ML + UEBA + detections",risk_det:"Detections",risk_corrob:"corroborated signals",risk_critical:"Critical",risk_high:"High",risk_moderate:"Moderate",risk_low:"Low",risk_minimal:"Minimal",g_title:"Action guide",g_what:"What it is",g_check:"To check",g_remed:"Remediation",g_correct:"Lasting fix",g_none:"No guidance for this detection.",g_hint:"click for the action guide",g_show:"Action guide ▸",empty_det:"No detection",
  k_attempts:"attempts",k_success:"successful",k_fail:"failures",k_countries:"countries",k_ips:"source IPs",ch_ok:"Successful",ch_ko:"Failures",succ_suffix:"successful",none_suffix:"0 successful",
  case_status:"Case status updated.",case_disp:"Disposition saved — the false-positive reduction model will adjust.",case_assign:"Case assigned.",case_note:"Investigation note added.",case_def:"Case updated."
 }
};
function t(k){const v=(I18N[LANG]||{})[k];return v!==undefined?v:((I18N.fr||{})[k]!==undefined?I18N.fr[k]:k);}
function applyI18n(){
  document.querySelectorAll("[data-i18n]").forEach(e=>e.textContent=t(e.getAttribute("data-i18n")));
  document.querySelectorAll("[data-i18n-ph]").forEach(e=>e.setAttribute("placeholder",t(e.getAttribute("data-i18n-ph"))));
  document.querySelectorAll("[data-i18n-al]").forEach(e=>e.setAttribute("aria-label",t(e.getAttribute("data-i18n-al"))));
  document.querySelectorAll("[data-i18n-t]").forEach(e=>e.setAttribute("title",t(e.getAttribute("data-i18n-t"))));
}
function updateLangBtn(){const b=$("#langLab");if(b)b.textContent=(LANG==="fr"?"EN":"FR");const g=$("#langBtn");if(g)g.setAttribute("title",t("t_lang"));}
function setLang(l){LANG=l;localStorage.setItem("soc_lang",l);document.documentElement.lang=l;applyI18n();
  const cur=((document.querySelector("#nav a.on")||{}).dataset||{}).p||"overview";
  const tt=$("#ptitle");if(tt)tt.textContent=(titles[LANG]||titles.fr)[cur];setDesc(cur);
  const hb=$("#helpBody");if(hb){hb.dataset.built="";hb.innerHTML="";if(typeof buildHelp==="function"&&$("#help")&&$("#help").classList.contains("on"))buildHelp();}
  if(typeof loadAll==="function")loadAll();updateLangBtn();}

// auth
function login(e){e.preventDefault();
  fetch(API+"/login",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({username:u.value,password:p.value})})
   .then(r=>r.ok?start():$("#lerr").textContent=(LANG==="en"?"Invalid credentials":"Identifiants invalides")).catch(()=>$("#lerr").textContent=(LANG==="en"?"Network error":"Erreur réseau"));}
function logout(){fetch(API+"/logout",{method:"POST",credentials:"same-origin"}).then(()=>location.reload());}
function start(){$("#login").style.display="none";$("#app").style.display="grid";
  document.documentElement.lang=LANG;applyI18n();updateLangBtn();
  const tt=$("#ptitle");if(tt)tt.textContent=(titles[LANG]||titles.fr).overview;setDesc("overview");
  document.body.classList.add("firstload");loadAll().then(()=>{try{deepLink();}catch(e){}});startLive();startRefresh();
  j("/guidance").then(r=>{GUIDANCE=r.guidance||{};}).catch(()=>{});}

// nav
const titles={
  fr:{soar:"SOAR — Blocages pare-feu",ops:"Exploitation du SIEM",overview:"Vue d'ensemble",incidents:"Incidents",detections:"Détections",entities:"Recherche d'entités",attack:"MITRE ATT&CK",graph:"Graphe d'attaque",twin:"Jumeau d'attaque — Exposition",ems:"Endpoint — FortiClient EMS",network:"Réseau & Infra — Aruba / Linux / DNS",deploy:"Déploiement / Agents",globe:"Carte mondiale — Flux temps réel",leaks:"Fuites & Dark Web",health:"Santé & Collecte",report:"Rapport",playbooks:"Playbooks de réponse"},
  en:{soar:"SOAR — Firewall blocks",ops:"SIEM operations",overview:"Overview",incidents:"Incidents",detections:"Detections",entities:"Entity search",attack:"MITRE ATT&CK",graph:"Attack graph",twin:"Attack twin — Exposure",ems:"Endpoint — FortiClient EMS",network:"Network & Infra — Aruba / Linux / DNS",deploy:"Deployment / Agents",globe:"World map — Live flows",leaks:"Leaks & Dark Web",health:"Health & Collection",report:"Report",playbooks:"Response playbooks"}};
const PDESC={
 fr:{
  overview:"<b>Posture en un coup d'œil</b> — indicateurs clés, activité des dernières 24 h, tactiques ATT&CK et flux d'événements en temps réel. Chaque indicateur est cliquable.",
  incidents:"<b>File de cas corrélés (oms-xdr)</b> — chaque incident regroupe plusieurs détections en kill-chain. Cliquez pour le traiter : statut, assignation, notes d'investigation.",
  detections:"<b>Toutes les détections taguées (24 h)</b> — filtrez par tactique ATT&CK ou par source ; cliquez une ligne pour la fiche complète de l'entité concernée.",
  attack:"<b>Matrice MITRE ATT&CK</b> — chaque cellule est une technique que vous détectez, colorée selon le volume d'activité réel. Le rouge signale une forte activité à investiguer.",
  graph:"<b>Graphe d'attaque</b> — relie les utilisateurs aux techniques qu'ils ont déclenchées. Taille du nœud = volume, couleur = tactique. Cliquez un nœud bleu pour la fiche entité.",
  twin:"<b>Jumeau d'attaque (oms-graph)</b> — reconstruit passivement les chemins d'exposition vers les joyaux (DC, SIEM, Veeam, PKI…). Montre où durcir en priorité (<b>chokepoints</b>), le <b>rayon de souffle</b> d'un compromis, les <b>points uniques</b>, et où <b>pré-positionner les leurres</b>. Défensif, lecture passive.",
  ems:"<b>Endpoint — FortiClient EMS</b> — télémétrie des postes via FortiClient EMS (syslog TLS) : <b>malware</b> détecté par l'AV, <b>vulnérabilités</b> critiques, <b>protection désactivée</b>, et l'activité par type/poste. Les événements apparaissent au fur et à mesure que les postes remontent.",
  network:"<b>Réseau & Infra</b> — sources on-prem ajoutées au SIEM : <b>switches Aruba</b> (échecs d'auth admin, changements de config, port-security, sessions — avec l'IP cliente), <b>serveurs Linux</b> (SSH/sudo/compte/fichiers sensibles) et <b>DNS</b> (modifs manuelles d'enregistrement sur le DC). L'activité bénigne (ports up/down, STP) est affichée pour le contexte ; les détections de sécurité ressortent.",
  deploy:"<b>Déploiement / Agents</b> — enrôlez n'importe quel hôte en une commande : un <b>one-liner</b> à copier (Windows <code>irm … | iex</code>, Linux <code>curl … | sudo bash</code>) qui vérifie les prérequis et converge (idempotent), ou le <b>téléchargement direct</b> des fichiers. Chaque bloc indique les prérequis et si le SIEM voit déjà l'hôte. Intégrité par CA TOFU + SHA256.",
  globe:"<b>Carte mondiale</b> — globe 3D des flux géolocalisés <b>monde → OMNITECH</b> (3 h) : chaque arc est un flux réel, <b style=\"color:#e5484d\">rouge = menace</b> (échec d'auth, blocage WAF, deny FortiGate…), <b style=\"color:#4cc2cf\">cyan = trafic</b>. Survolez un arc pour le détail ; le panneau liste les pays attaquants et les flux en direct. Données GeoIP réelles sur les IP publiques.",
  leaks:"<b>Fuites & Dark Web</b> — surveille les sites d'extorsion ransomware (RansomLook), les comptes exposés (HIBP/Dehashed) et le code public (GitHub).",
  health:"<b>Santé de la collecte</b> — volume et fraîcheur de chaque source. Une source qui décroche = angle mort, alerté automatiquement (preuve ISO A.8.15).",
  report:"<b>Rapport de posture</b> — synthèse exécutive imprimable (PDF) pour la direction et l'audit ISO. Bouton « Imprimer / PDF » en haut à droite.",
  playbooks:"<b>Playbooks de réponse</b> — pour chaque détection : ce que c'est, comment trier (vrai/faux positif), comment remédier et corriger durablement. Cherchez, ou parcourez par tactique ATT&CK.",
  entities:"<b>Recherche d'entités</b> — cherchez n'importe quel compte ou machine et ouvrez son <b>dossier 360°</b> : identité unifiée (comptes liés), authentifications, logons, détections, chronologie et guides d'action. Ou parcourez les plus actifs."
 },
 en:{
  overview:"<b>Posture at a glance</b> — key indicators, last-24h activity, ATT&CK tactics and a real-time event feed. Every indicator is clickable.",
  incidents:"<b>Correlated case queue (oms-xdr)</b> — each incident groups several detections into a kill-chain. Click to handle it: status, assignment, investigation notes.",
  detections:"<b>All tagged detections (24h)</b> — filter by ATT&CK tactic or by source; click a row for the full entity profile.",
  attack:"<b>MITRE ATT&CK matrix</b> — each cell is a technique you detect, colored by real activity volume. Red flags high activity to investigate.",
  graph:"<b>Attack graph</b> — links users to the techniques they triggered. Node size = volume, color = tactic. Click a blue node for the entity profile.",
  twin:"<b>Attack twin (oms-graph)</b> — passively reconstructs exposure paths to the crown jewels (DC, SIEM, Veeam, PKI…). Shows where to harden first (<b>chokepoints</b>), the <b>blast radius</b> of a compromise, <b>single points of failure</b>, and where to <b>pre-position decoys</b>. Defensive, passive read.",
  ems:"<b>Endpoint — FortiClient EMS</b> — endpoint telemetry via FortiClient EMS (syslog TLS): <b>malware</b> caught by the AV, critical <b>vulnerabilities</b>, <b>protection disabled</b>, and activity by type/host. Events appear as endpoints report in.",
  network:"<b>Network & Infra</b> — on-prem sources added to the SIEM: <b>Aruba switches</b> (admin auth failures, config changes, port-security, sessions — with the client IP), <b>Linux servers</b> (SSH/sudo/account/file tampering) and <b>DNS</b> (manual record changes on the DC). Benign activity (port up/down, STP) is shown for context; security detections stand out.",
  globe:"<b>World map</b> — 3D globe of geolocated flows <b>world → OMNITECH</b> (3 h): each arc is a real flow, <b style=\"color:#e5484d\">red = threat</b> (auth failure, WAF block, FortiGate deny…), <b style=\"color:#4cc2cf\">cyan = traffic</b>. Hover an arc for detail; the panel lists attacking countries and live flows. Real GeoIP data on public IPs.",
  deploy:"<b>Deployment / Agents</b> — enroll any host with one command: a copy-paste <b>one-liner</b> (Windows <code>irm … | iex</code>, Linux <code>curl … | sudo bash</code>) that checks prerequisites and converges (idempotent), or <b>direct download</b> of the files. Each block lists prerequisites and whether the SIEM already sees the host. Integrity via CA TOFU + SHA256.",
  leaks:"<b>Leaks & Dark Web</b> — monitors ransomware extortion sites (RansomLook), exposed accounts (HIBP/Dehashed) and public code (GitHub).",
  health:"<b>Collection health</b> — volume and freshness of each source. A source going dark = blind spot, alerted automatically (ISO A.8.15 evidence).",
  report:"<b>Posture report</b> — printable executive summary (PDF) for management and ISO audit. “Print / PDF” button at top right.",
  playbooks:"<b>Response playbooks</b> — for each detection: what it is, how to triage (true/false positive), how to remediate and harden. Search, or browse by ATT&CK tactic.",
  entities:"<b>Entity search</b> — search any account or machine and open its <b>360° dossier</b>: unified identity (linked accounts), authentications, logons, detections, timeline and action guides. Or browse the most active."
 }
};
function setDesc(pg){if($("#pdesc"))$("#pdesc").innerHTML=(PDESC[LANG]||PDESC.fr)[pg]||"";}
document.querySelectorAll("#nav a").forEach(a=>a.onclick=()=>{
  document.querySelectorAll("#nav a").forEach(x=>x.classList.toggle("on",x===a));
  const pg=a.dataset.p; document.querySelectorAll(".page").forEach(s=>s.classList.toggle("on",s.id==="p-"+pg));
  $("#ptitle").textContent=(titles[LANG]||titles.fr)[pg];setDesc(pg);
  if(pg==="graph"){loadScript("/soc/cytoscape.min.js").then(()=>j("/graph")).then(g=>{renderGraph(g);gPopulate();setTimeout(applyGraphFilter,80);}).catch(()=>{});}
  if(pg==="report"){j("/report").then(r=>renderReport(r)).catch(()=>{});}
  if(pg==="playbooks"){var s=$("#pbSearch");renderPlaybooks(s?s.value:"");}
  if(pg==="entities"){loadEntities();}
  if(pg==="twin"){j("/attack-graph").then(d=>renderTwin(d)).catch(()=>{});}
  if(pg==="ems"){j("/fortiems").then(d=>renderEms(d)).catch(()=>{});}
  if(pg==="network"){j("/network").then(d=>renderNetwork(d)).catch(()=>{});}
  if(pg==="deploy"){j("/deploy").then(d=>renderDeploy(d)).catch(()=>{});}
  if(pg==="soar"&&window.loadSoar){loadSoar();}
  if(pg==="ops"&&window.loadOps){loadOps();}
  if(pg==="globe"){const gw=$("#globeCanvas");if(gw&&!window.Globe)gw.innerHTML='<div class="muted" style="position:absolute;inset:0;display:grid;place-items:center">Chargement de la carte 3D…</div>';
    loadScript("/soc/globe.gl.min.js").then(()=>j("/geo-flows")).then(d=>{renderGlobe(d);setTimeout(()=>{if(GLOBE&&GLOBE.width){const el=$("#globeCanvas");GLOBE.width(el.clientWidth).height(el.clientHeight);}},120);}).catch(()=>{});}});
document.querySelectorAll("#nav a").forEach((a,i)=>{if(i<9)a.title=(LANG==="en"?"Shortcut ":"Raccourci ")+(i+1);});
function renderEms(d){const w=$("#emsWrap");if(!w)return;d=d||{};const EN=LANG==="en";
  const sc=s=>s==="critique"?"#fb3b53":s==="eleve"?"#f5a623":"#38bdf8";
  const K=(v,l,col)=>'<div class="kpi '+(col||'cy')+'"><div class="lab">'+l+'</div><div class="val mono">'+(v||0).toLocaleString("fr")+'</div></div>';
  let H='<div class="card"><h3><svg class="svi"><use href="#i-cpu"></use></svg> '+(EN?"Endpoint telemetry (FortiClient EMS)":"Télémétrie endpoint (FortiClient EMS)")+'<span class="tag">'+(d.days||7)+'j · syslog TLS</span></h3>'
    +'<div class="grid kpis">'+K(d.malware,(EN?"malware":"malware"),(d.malware?'red':'cy'))+K(d.vuln,(EN?"critical vuln":"vuln. critiques"),(d.vuln?'amb':'cy'))+K(d.av_off,(EN?"protection off":"protection off"),(d.av_off?'red':'cy'))+K(d.total,(EN?"events":"événements"),'cy')+'</div></div>';
  if(!d.total){H+='<div class="card"><p class="muted">'+(EN?"No FortiClient EMS event yet — events appear as endpoints report (AV, vulnerabilities, status). Ingestion is live (TLS).":"Aucun événement FortiClient EMS pour l'instant — ils apparaissent au fur et à mesure (AV, vulnérabilités, statut). L'ingestion est active (TLS).")+'</p></div>';w.innerHTML=H;return;}
  // top sous-types + top postes (2 colonnes)
  H+='<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(300px,1fr))">';
  const st=d.subtypes||[];const sm=st.length?st[0].n:1;
  H+='<div class="card"><h3>'+(EN?"Event types":"Types d'événements")+'</h3><div class="feed">'+st.map(x=>'<div class="frow" style="display:flex;align-items:center;gap:8px"><span class="mono" style="min-width:36px;text-align:right;color:var(--cy)">'+x.n+'</span><span class="bar" style="height:7px;border-radius:4px;background:#38bdf8;width:'+Math.max(8,Math.round(100*x.n/sm))+'%;display:inline-block"></span> '+esc(x.k)+'</div>').join('')+'</div></div>';
  const ht=d.hosts||[];
  H+='<div class="card"><h3>'+(EN?"Top endpoints":"Top postes")+'</h3><div class="feed">'+ht.map(x=>'<div class="frow" data-onclick="openEntity(\''+_jsq(x.host)+'\',\''+_jsq(x.host)+'\')" title="'+(EN?"Open dossier":"Dossier")+'" style="cursor:pointer;display:flex;gap:8px"><span class="mono" style="min-width:36px;text-align:right;color:var(--cy)">'+x.n+'</span> '+esc(x.host)+'</div>').join('')+'</div></div>';
  H+='</div>';
  // événements récents
  const ev=d.events||[];
  H+='<div class="card"><h3>'+(EN?"Recent events":"Événements récents")+'</h3><div class="feed">'+ev.map(e=>'<div class="frow" style="border-left:3px solid '+(e.tag?sc(e.sev):"#2a3654")+';padding-left:8px">'
    +'<div style="display:flex;align-items:center;gap:8px"><span class="ts" style="color:var(--dim);font-size:11px">'+(e.ts?e.ts.slice(11,19):'')+'</span>'+(e.tag?'<span class="chip">'+nice(e.tag)+'</span>':'<span class="muted" style="font-size:11px">'+esc(e.subtype||'')+'</span>')+(e.host?' <b style="font-size:12px">'+esc(e.host)+'</b>':'')+(e.threat?' <span style="color:#fb3b53;font-size:12px">'+esc(e.threat)+'</span>':'')+'</div>'
    +'<div class="muted" style="font-size:12px;margin-top:2px">'+esc((e.msg||'').slice(0,140))+'</div></div>').join('')+'</div></div>';
  w.innerHTML=H;}
function renderNetwork(d){const w=$("#netWrap");if(!w)return;d=d||{};const EN=LANG==="en";
  const A=d.aruba||{},L=d.linux||{},N=d.dns||{};
  const K=(v,l,col)=>'<div class="kpi '+(col||'cy')+'"><div class="lab">'+l+'</div><div class="val mono">'+(v||0).toLocaleString("fr")+'</div></div>';
  const secCount=o=>(o.tags||[]).reduce((s,x)=>s+x.n,0);
  const totalSec=secCount(A)+secCount(L)+secCount(N);
  let H='<div class="card"><h3><svg class="svi"><use href="#i-network"></use></svg> '+(EN?"Network & infrastructure":"Réseau & infrastructure")+'<span class="tag">'+(d.days||7)+(EN?'d · Aruba / Linux / DNS':'j · Aruba / Linux / DNS')+'</span></h3>'
    +'<div class="grid kpis">'
    +K(A.switches_seen,(EN?"Aruba switches":"switches Aruba"),'cy')
    +K(A.total,(EN?"switch events":"events switch"),'cy')
    +K(L.total,(EN?"Linux events":"events Linux"),'cy')
    +K(N.total,(EN?"DNS events":"events DNS"),'cy')
    +K(totalSec,(EN?"security detections":"détections sécurité"),(totalSec?'amb':'cy'))
    +'</div></div>';
  const tagFeed=(tags)=>tags&&tags.length? tags.map(x=>'<div class="frow" style="display:flex;gap:8px;align-items:center"><span class="chip">'+nice(x.k)+'</span><span class="mono" style="color:var(--cy)">'+x.n+'</span></div>').join('') : '<div class="muted" style="font-size:12px">'+(EN?"no security detection":"aucune détection")+'</div>';
  const hostFeed=(hosts)=>hosts&&hosts.length? hosts.map(x=>'<div class="frow" style="display:flex;gap:8px"><span class="mono" style="min-width:30px;text-align:right;color:var(--cy)">'+x.n+'</span> '+esc(x.k)+'</div>').join('') : '<div class="muted" style="font-size:12px">—</div>';
  const srcCard=(title,o)=>'<div class="card"><h3>'+title+'<span class="tag">'+(o.total||0)+(EN?' ev':' év')+'</span></h3>'
    +'<div class="muted" style="font-size:11px;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px">'+(EN?"Detections":"Détections")+'</div>'+tagFeed(o.tags)
    +'<div class="muted" style="font-size:11px;margin:10px 0 6px;text-transform:uppercase;letter-spacing:.5px">'+(EN?"Top hosts":"Top hôtes")+'</div>'+hostFeed(o.hosts)+'</div>';
  H+='<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr))">'
    +srcCard((EN?"Aruba switches":"Switches Aruba"),A)+srcCard("Linux",L)+srcCard("DNS (DC)",N)+'</div>';
  const subs=A.subsystems||[],sm=subs.length?subs[0].n:1,cli=A.clients||[];
  if(subs.length||cli.length){
    H+='<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(300px,1fr))">';
    if(subs.length)H+='<div class="card"><h3>'+(EN?"Aruba — subsystems":"Aruba — sous-systèmes")+'</h3><div class="feed">'+subs.map(x=>'<div class="frow" style="display:flex;align-items:center;gap:8px"><span class="mono" style="min-width:36px;text-align:right;color:var(--cy)">'+x.n+'</span><span class="bar" style="height:7px;border-radius:4px;background:#38bdf8;width:'+Math.max(8,Math.round(100*x.n/sm))+'%;display:inline-block"></span> '+esc(x.k)+'</div>').join('')+'</div></div>';
    if(cli.length)H+='<div class="card"><h3>'+(EN?"Aruba — client IPs (sessions/auth)":"Aruba — IP clientes (sessions/auth)")+'</h3><div class="feed">'+cli.map(x=>'<div class="frow" style="display:flex;gap:8px"><span class="mono" style="min-width:36px;text-align:right;color:var(--cy)">'+x.n+'</span> '+esc(x.k)+'</div>').join('')+'</div></div>';
    H+='</div>';
  }
  const ev=A.events||[];
  if(ev.length){
    H+='<div class="card"><h3>'+(EN?"Aruba — recent activity":"Aruba — activité récente")+'</h3><div class="feed">'+ev.map(e=>'<div class="frow" style="border-left:3px solid '+(e.tag?"#f5a623":"#2a3654")+';padding-left:8px">'
      +'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><span class="ts" style="color:var(--dim);font-size:11px">'+(e.ts?e.ts.slice(5,19).replace("T"," "):'')+'</span>'
      +(e.tag?'<span class="chip">'+nice(e.tag)+'</span>':(e.sub?'<span class="muted" style="font-size:11px">'+esc(e.sub)+'</span>':''))
      +(e.sw?' <b style="font-size:12px">'+esc(e.sw)+'</b>':'')
      +(e.client?' <span style="color:#22d3ee;font-size:12px">← '+esc(e.client)+'</span>':'')
      +(e.port?' <span class="muted" style="font-size:11px">port '+esc(e.port)+'</span>':'')+'</div>'
      +'<div class="muted" style="font-size:12px;margin-top:2px">'+esc((e.msg||'').slice(0,150))+'</div></div>').join('')+'</div></div>';
  }
  if(!A.total&&!L.total&&!N.total)H='<div class="card"><p class="muted">'+(EN?"No network/infra event yet.":"Aucun événement réseau/infra pour l'instant.")+'</p></div>';
  w.innerHTML=H;}
function copyTxt(btn,txt){try{navigator.clipboard.writeText(txt).then(function(){var o=btn.getAttribute("data-l")||btn.textContent;btn.setAttribute("data-l",o);btn.textContent=(LANG==="en"?"Copied ✓":"Copié ✓");setTimeout(function(){btn.textContent=o;},1400);});}catch(e){}}
function _kb(n){n=n||0;return n>=1048576?(n/1048576).toFixed(1)+" Mo":n>=1024?(n/1024).toFixed(0)+" Ko":n+" o";}
function renderDeploy(d){const w=$("#depWrap");if(!w)return;d=d||{};const EN=LANG==="en";
  const S=d.siem||{},P=(S.ports||{}),E=d.enrolled||{},AR=d.artifacts||[];
  const BTN='display:inline-block;padding:4px 9px;margin:2px 4px 2px 0;border:1px solid var(--bd);border-radius:6px;background:#0c1525;color:var(--cy);font-size:12px;cursor:pointer;text-decoration:none';
  const K=(v,l)=>'<div class="kpi cy"><div class="lab">'+l+'</div><div class="val mono">'+(typeof v==="number"?v.toLocaleString("fr"):esc(v))+'</div></div>';
  const winN=(E.windows||[]).length,linN=(E.linux||[]).length,aruN=(E.aruba||[]).length;
  let H='<div class="card"><h3><svg class="svi"><use href="#i-doc"></use></svg> '+(EN?"Host enrollment center":"Centre d'enrôlement des hôtes")+'<span class="tag">'+esc(S.fqdn||"")+'</span></h3>'
    +'<div class="grid kpis">'+K(AR.length,(EN?"artifacts":"artefacts"))+K(winN,(EN?"Windows seen":"Windows vus"))+K(linN,(EN?"Linux seen":"Linux vus"))+K(aruN,(EN?"Aruba seen":"Aruba vus"))+'</div>'
    +'<div class="muted" style="font-size:12px;margin-top:8px">SIEM '+esc(S.ip||"")+' · Windows '+(P.windows||5044)+' (Beats TLS) · Linux '+(P.linux||1519)+' (syslog) · Aruba '+(P.aruba||1520)+' · console '+(P.console||443)+'</div></div>';
  const block=(title,icon,oneliner,files,prereq,hosts,note)=>{
    const dls=(files||[]).map(f=>'<a style="'+BTN+'" href="/kit/'+encodeURIComponent(f)+'" download>'+esc(f)+'</a>').join('');
    const seen=(hosts||[]).length;
    const seenTag=note?('<span class="tag">'+esc(note)+'</span>')
      :('<span class="tag" style="border-color:'+(seen?'#2dd4a7':'#39507a')+';color:'+(seen?'#2dd4a7':'#9fb2cf')+'">'+(seen?seen+(EN?' enrolled':' enrôlés'):(EN?'none yet':'aucun'))+'</span>');
    let h='<div class="card"><h3>'+(icon?'<svg class="svi"><use href="#'+icon+'"></use></svg> ':'')+esc(title)+seenTag+'</h3>';
    if(oneliner)h+='<div style="display:flex;gap:8px;align-items:center;background:#0b1220;border:1px solid var(--bd);padding:8px;border-radius:6px;margin:4px 0"><code style="flex:1;overflow:auto;white-space:nowrap;color:#cbd5e1;font-size:12px">'+esc(oneliner)+'</code><button style="'+BTN+'" data-onclick="copyTxt(this,'+JSON.stringify(oneliner).replace(/"/g,'&quot;')+')">'+(EN?"Copy":"Copier")+'</button></div>';
    if(dls)h+='<div style="margin:8px 0 4px">'+dls+'</div>';
    if(prereq)h+='<div class="muted" style="font-size:12px">'+(EN?"Prerequisites":"Prérequis")+' : '+esc(prereq)+'</div>';
    if(seen){const last=hosts[0].last?(' · '+(EN?"last":"dern.")+' '+esc(hosts[0].last.slice(0,16))):'';
      h+='<div class="muted" style="font-size:11px;margin-top:4px">'+esc(hosts.slice(0,6).map(x=>x.host).join(', '))+(hosts.length>6?'…':'')+last+'</div>';}
    return h+'</div>';};
  const win='irm https://'+(S.fqdn||"")+'/kit/install.ps1 | iex';
  const lin='curl -fsSL https://'+(S.fqdn||"")+'/kit/install.sh | sudo bash -s -- '+(S.ip||"");
  H+='<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(330px,1fr))">';
  H+=block("Windows (Winlogbeat + Sysmon + audit)","i-cpu",win,
        ["install.ps1","Install-OmniSiem-NinjaOne.ps1","winlogbeat.yml","sysmonconfig-omnitech.xml","audit-baseline.csv","omnitech-rootca.pem"],
        "Admin, PowerShell 5.1+, 64-bit, TCP 5044+443",E.windows);
  H+=block("Linux — Debian / Ubuntu","i-network",lin,["install.sh","omnitech-rootca.pem"],
        "root/sudo, rsyslog, TCP 1519",E.linux);
  H+=block("Linux — RHEL / Rocky / SUSE","i-network",lin,["install.sh"],
        "root/sudo, dnf/zypper, rsyslog, TCP 1519",E.linux);
  H+=block("Switch Aruba (AOS-S)","i-network",null,null,
        "syslog → "+(S.ip||"")+" UDP/TCP 1520 : logging "+(S.ip||""),E.aruba,(EN?"reference":"référence"));
  H+='</div>';
  if(AR.length){
    H+='<div class="card"><h3>'+(EN?"Artifacts & integrity (SHA-256)":"Artefacts & intégrité (SHA-256)")+'<span class="tag">/kit/SHA256SUMS</span></h3><div class="feed">'
      +AR.map(a=>'<div class="frow" style="display:flex;gap:10px;align-items:center;font-size:12px"><a style="'+BTN+'" href="/kit/'+encodeURIComponent(a.name)+'" download>'+esc(a.name)+'</a><span class="muted mono">'+_kb(a.size)+'</span><span class="mono" style="color:var(--dim);overflow:hidden;text-overflow:ellipsis;flex:1" title="'+esc(a.sha256)+'">'+esc((a.sha256||'').slice(0,24))+'…</span></div>').join('')
      +'</div></div>';
  }
  w.innerHTML=H;}
let GLOBE=null,_GD=null,GLOBE_MEN=false,GLOBE_CC="";
function _ccflag(cc){if(!cc||cc.length!==2)return"";try{return String.fromCodePoint.apply(null,[...cc.toUpperCase()].map(c=>0x1F1E6+c.charCodeAt(0)-65));}catch(e){return"";}}
function _globeArcs(){const d=_GD||{};const OMS=d.oms||{lat:45.585,lng:5.274};
  let A=(d.arcs||[]);if(GLOBE_MEN)A=A.filter(a=>a.kind==="menace");
  return A.map(a=>{const dim=GLOBE_CC&&a.cc!==GLOBE_CC;const men=a.kind==="menace";
    return {startLat:a.lat,startLng:a.lng,endLat:OMS.lat,endLng:OMS.lng,_k:a.kind,_n:a.n,_t:a.threat,_cc:a.cc,_src:a.src,_dim:dim,
      color:dim?['rgba(120,140,165,0)','rgba(120,140,165,.10)']:(men?['rgba(229,72,77,0)','rgba(229,72,77,.95)']:['rgba(76,194,207,0)','rgba(76,194,207,.5)'])};});}
function _globePts(){const d=_GD||{};const OMS=d.oms||{lat:45.585,lng:5.274};
  let A=(d.arcs||[]);if(GLOBE_MEN)A=A.filter(a=>a.kind==="menace");
  const pts=A.map(a=>({lat:a.lat,lng:a.lng,_n:a.n,_cc:a.cc,color:(GLOBE_CC&&a.cc!==GLOBE_CC)?'#3a4658':(a.kind==="menace"?'#e5484d':'#4cc2cf'),size:Math.min(.85,Math.log10((a.n||1)+1)*.16)}));
  pts.push({lat:OMS.lat,lng:OMS.lng,color:'#22d3ee',size:1.0,_oms:1,_cc:'OMS'});return pts;}
function globeApply(){if(GLOBE)GLOBE.arcsData(_globeArcs()).pointsData(_globePts());}
function renderGlobe(d){d=d||{};const el=$("#globeCanvas");if(!el||!window.Globe)return;const EN=LANG==="en";_GD=d;
  const OMS=d.oms||{lat:45.585,lng:5.274,label:"OMNITECH"};
  if(!GLOBE){
    GLOBE=Globe()(el)
      .backgroundColor('rgba(0,0,0,0)')
      .globeImageUrl('/soc/earth-night.jpg').bumpImageUrl('/soc/earth-topology.png')
      .showAtmosphere(true).atmosphereColor('#3a6f93').atmosphereAltitude(.2)
      .arcColor('color').arcDashLength(.45).arcDashGap(.6).arcDashInitialGap(()=>Math.random())
      .arcDashAnimateTime(1400).arcStroke(a=>a._dim?0.18:(a._k==="menace"?0.55:0.28)).arcAltitudeAutoScale(.45)
      .pointColor('color').pointAltitude(p=>p._oms?0.04:0.008).pointRadius('size').pointResolution(6)
      .ringColor(()=>t=>'rgba(34,211,238,'+(1-t)+')').ringMaxRadius(5).ringPropagationSpeed(2.2).ringRepeatPeriod(1100)
      .onArcHover(a=>globeHover(a,EN))
      .onArcClick(a=>{if(!a)return;GLOBE_CC=(GLOBE_CC===a._cc)?"":a._cc;GLOBE.pointOfView({lat:a.startLat,lng:a.startLng,altitude:1.6},900);globeApply();globeRail(_GD,EN);})
      .onPointClick(p=>{if(p&&GLOBE)GLOBE.pointOfView({lat:p.lat,lng:p.lng,altitude:p._oms?2.2:1.4},900);});
    const _fit=()=>{const s=el.parentElement;if(s&&GLOBE){GLOBE.width(s.clientWidth).height(s.clientHeight);}};
    _fit();setTimeout(_fit,200);setTimeout(_fit,700);
    GLOBE.pointOfView({lat:OMS.lat,lng:OMS.lng,altitude:2.4},0);
    if(GLOBE.controls){const c=GLOBE.controls();c.autoRotate=true;c.autoRotateSpeed=.36;c.enableDamping=true;c.minDistance=200;c.maxDistance=600;}
    window.addEventListener("resize",_fit);
  }
  GLOBE._oms=OMS;
  GLOBE.ringsData([{lat:OMS.lat,lng:OMS.lng}]);
  globeApply();globeRail(d,EN);}
let GLOBE_DAY=false;
function globeToggleDay(){if(!GLOBE)return;GLOBE_DAY=!GLOBE_DAY;
  GLOBE.globeImageUrl(GLOBE_DAY?'/soc/earth-blue-marble.jpg':'/soc/earth-night.jpg');
  const b=document.getElementById('globeDayBtn');if(b)b.textContent=GLOBE_DAY?'☾ Nuit':'☀ Jour';}
function globeMenace(){GLOBE_MEN=!GLOBE_MEN;const b=document.getElementById('globeMenBtn');if(b)b.classList.toggle('on',GLOBE_MEN);globeApply();}
function globeReset(){GLOBE_CC="";globeApply();if(GLOBE&&GLOBE._oms)GLOBE.pointOfView({lat:GLOBE._oms.lat,lng:GLOBE._oms.lng,altitude:2.4},900);if(_GD)globeRail(_GD,LANG==="en");}
function globeHover(a,EN){const h=$("#globeHover");if(!h)return;if(!a){h.style.display="none";return;}
  h.style.display="block";
  h.innerHTML='<b>'+_ccflag(a._cc)+' '+esc(a._cc||'?')+'</b> &rarr; OMNITECH<br><span class="mono">'+(a._n||0).toLocaleString("fr")+'</span> '+(EN?"flows":"flux")
    +' · <span style="color:#e5484d" class="mono">'+(a._t||0).toLocaleString("fr")+'</span> '+(EN?"threats":"menaces")+(a._src?' · '+esc(a._src):'');}
function globeRail(d,EN){const T=d.totals||{};
  const K=(v,l,col)=>'<div class="kpi '+(col||'cy')+'" style="padding:13px 15px"><div class="lab">'+l+'</div><div class="val mono" style="font-size:25px">'+(v||0).toLocaleString("fr")+'</div></div>';
  if($("#globeKpis"))$("#globeKpis").innerHTML=K(T.menace,(EN?"threats · 3h":"menaces · 3h"),(T.menace?'red':'cy'))+K(T.flux,(EN?"flows · 3h":"flux · 3h"),'cy');
  const top=d.top_countries||[],mx=top.length?top[0].n:1;
  if($("#globeTop"))$("#globeTop").innerHTML=top.map(c=>{const on=GLOBE_CC===c.cc;
    return '<div data-onclick="globeFocusCC(\''+esc(c.cc)+'\')" title="Focus" style="display:flex;align-items:center;gap:8px;margin:5px 0;cursor:pointer;padding:2px 5px;border-radius:6px;'+(on?'background:rgba(229,72,77,.12)':'')+'">'
    +'<span class="gflag" style="width:20px">'+_ccflag(c.cc)+'</span><span style="width:26px" class="mono">'+esc(c.cc)+'</span>'
    +'<span style="flex:1;height:7px;border-radius:4px;background:linear-gradient(90deg,#e5484d,#7a1f27);width:'+Math.max(6,Math.round(100*c.n/mx))+'%;opacity:'+(on?1:.82)+'"></span>'
    +'<span class="mono" style="color:var(--cy);min-width:54px;text-align:right">'+c.n.toLocaleString("fr")+'</span></div>';}).join('')||'<div class="muted">—</div>';
  let rec=d.recent||[];if(GLOBE_CC)rec=rec.filter(e=>e.cc===GLOBE_CC);
  const foc=GLOBE_CC?'<div style="display:flex;align-items:center;gap:6px;margin-bottom:7px"><span class="chip" style="background:rgba(229,72,77,.16);color:#e5484d;border-color:rgba(229,72,77,.32)">'+_ccflag(GLOBE_CC)+' '+esc(GLOBE_CC)+' · focus</span><button class="gctrl-btn" style="padding:1px 8px" data-onclick="globeReset()">✕</button></div>':'';
  if($("#globeFeed"))$("#globeFeed").innerHTML=foc+(rec.map(e=>'<div style="border-left:2px solid #e5484d;padding-left:8px;margin:7px 0">'
    +'<div style="display:flex;gap:7px;align-items:center"><span class="gflag">'+_ccflag(e.cc)+'</span><b style="font-size:12px">'+nice(e.what||'')+'</b><span style="margin-left:auto;color:var(--dim);font-size:11px" class="mono">'+(e.ts?e.ts.slice(11,19):'')+'</span></div>'
    +'<div class="muted mono" style="font-size:11px;margin-top:2px">'+esc(e.ip||'')+(e.city&&e.city!=="N/A"?' · '+esc(e.city):'')+' · '+esc(e.src||'')+'</div></div>').join('')||'<div class="muted">'+(EN?"no flow for this country":"aucun flux pour ce pays")+'</div>');}
function globeFocusCC(cc){GLOBE_CC=(GLOBE_CC===cc)?"":cc;
  if(GLOBE_CC&&_GD){const a=(_GD.arcs||[]).find(x=>x.cc===cc);if(a&&GLOBE)GLOBE.pointOfView({lat:a.lat,lng:a.lng,altitude:1.6},900);}
  globeApply();if(_GD)globeRail(_GD,LANG==="en");}
function renderPlaybooks(q){const body=$("#pbBody");if(!body)return;
  if(!Object.keys(GUIDANCE).length){j("/guidance").then(r=>{GUIDANCE=r.guidance||{};renderPlaybooks(q);}).catch(()=>{});return;}
  q=(q||"").trim().toLowerCase();
  const groups={};
  Object.keys(GUIDANCE).forEach(tag=>{const g=GUIDANCE[tag];
    const hay=(tag+" "+(g.name||"")+" "+(g.technique||"")+" "+(g.tactic||"")+" "+(g.ce_que_cest||"")+" "+(g.remediation||"")).toLowerCase();
    if(q&&hay.indexOf(q)<0)return;
    const tac=g.tactic||"Autre";(groups[tac]=groups[tac]||[]).push(tag);});
  const tacs=Object.keys(groups).sort();
  if(!tacs.length){body.innerHTML='<div class="muted gpad">'+t("pb_none")+'</div>';return;}
  body.innerHTML=tacs.map(tac=>{
    const items=groups[tac].sort().map(tag=>{const g=GUIDANCE[tag];
      return '<div class="pbcard"><div class="pbhd"><b>'+nice(tag)+'</b>'+(g.technique?'<span class="srcb">'+esc(g.technique)+'</span>':'')+(g.severity?'<span class="pbsev '+esc(g.severity)+'">'+esc(g.severity)+'</span>':'')+'</div>'+guidanceBlock(tag)+'</div>';}).join("");
    return '<div class="pbgrp"><div class="pbtac" style="border-color:'+(TACCOL[tac]||"#39507a")+';color:'+(TACCOL[tac]||"#9fb2cf")+'">'+esc(tac)+' · '+groups[tac].length+'</div>'+items+'</div>';
  }).join("");}

// charts
if(window.Chart){Chart.defaults.color="#7c8aa6";Chart.defaults.font.family="Segoe UI";Chart.defaults.borderColor="rgba(255,255,255,.05)";}
const charts={};
function mk(id,cfg){if(!window.Chart||!$("#"+id))return;if(charts[id])charts[id].destroy();charts[id]=new Chart($("#"+id),cfg);}
const noLeg={plugins:{legend:{display:false}}};

async function loadAll(){
  RELOADING=true;setSpin(true);tickUpd();
  try{
    const [k,ts,tac,det,src,inc,mtx]=await Promise.all([
      j("/kpis"),j("/timeseries"),j("/by-tactic"),j("/top-detections"),j("/top-sources"),j("/cases"),j("/attack-matrix")]);
    renderKpis(k.kpis); renderTs(ts.series); renderTac(tac.data); renderDet(det.data);
    renderSrc(src.data); renderMatrix(mtx.matrix); renderCases(inc.cases); loadDetections();
    j("/leaks2").then(l=>renderLeaks(l)).catch(()=>{});
    j("/health").then(h=>renderHealth(h)).catch(()=>{});
    j("/risk").then(r=>renderRisk(r)).catch(()=>{});
    j("/kpi-trend").then(t=>renderKpiTrend(t.trend)).catch(()=>{});
    if(window.loadTodo)loadTodo();
    j("/geo").then(g=>renderGeo(g)).catch(()=>{});
    j("/attack-graph").then(a=>renderSentinelPosture(a)).catch(()=>{});
    // /graph et /report : charges a l'ouverture de leur onglet (cf. routeur #nav) -
    // evite de relancer le graphe lourd + la matrice 300-termes toutes les 60 s.
  }catch(e){if(e==="auth"){toastWarn("Session expirée — reconnexion à la console SOC…",{title:"Session",sticky:true});setTimeout(()=>location.reload(),1200);}else{toastNet();}}
  finally{RELOADING=false;setSpin(false);document.body.classList.remove("firstload");markUpdated();}
}
let TOPE=[];let MLT=[];let GUIDANCE={};
function toggleG(id){const e=$("#"+id);if(e)e.style.display=e.style.display==="none"?"block":"none";}
function guidanceBlock(tag){const g=GUIDANCE[tag];
  if(!g||!(g.ce_que_cest||g.remediation))return '<div class="gpad muted">'+t("g_none")+'</div>';
  const row=(lbl,v,cls)=>v?`<div class="grow ${cls}"><span class="glbl">${lbl}</span><span class="gval">${esc(v)}</span></div>`:'';
  return '<div class="gcard">'+row(t("g_what"),g.ce_que_cest,"gw")+row(t("g_check"),g.a_verifier,"gc")+row(t("g_remed"),g.remediation,"gr")+row(t("g_correct"),g.correction,"gf")+'</div>';}
function guidanceForMitre(mitreStr){
  if(!mitreStr||!Object.keys(GUIDANCE).length)return "";
  const techs=(mitreStr+"").split(/[,;]/).map(s=>s.trim()).filter(Boolean);
  if(!techs.length)return "";
  const seen={},tags=[];
  Object.keys(GUIDANCE).forEach(tag=>{const tech=GUIDANCE[tag].technique;
    if(tech&&techs.indexOf(tech)>=0&&!seen[tech]){seen[tech]=1;tags.push(tag);}});
  if(!tags.length)return "";
  return `<div class="blk"><div class="lbl">${t("g_title")}</div>`+tags.map(tag=>`<div class="pbcard"><div class="pbhd"><b>${nice(tag)}</b><span class="srcb">${esc(GUIDANCE[tag].technique)}</span></div>${guidanceBlock(tag)}</div>`).join("")+`</div>`;}
// --- Page Entités : recherche comptes/machines -> dossier 360° ---
let ENTB={users:[],machines:[]},ENTS=[];
function loadEntities(){loadWatchlist();j("/entities").then(d=>{ENTB=d||{users:[],machines:[]};
  $("#entUsers").innerHTML=(ENTB.users||[]).map((e,i)=>entRow(e,'u',i)).join("")||'<div class="muted gpad">—</div>';
  $("#entMachines").innerHTML=(ENTB.machines||[]).map((e,i)=>entRow(e,'m',i)).join("")||'<div class="muted gpad">—</div>';}).catch(()=>{});}
let WATCHL=[];
function loadWatchlist(){var w=$("#entWatch");if(!w)return;
  j("/watchlist").then(d=>{WATCHL=(d&&d.watchlist)||[];
    w.innerHTML=WATCHL.length?('<div class="lbl2">'+ic("eyeoff")+' '+t("watch_section")+' ('+WATCHL.length+')</div>'+WATCHL.map((e,i)=>'<div class="entrow watchrow" data-onclick="openWatch('+i+')">'+rkChip(e.risk)+'<span class="entk">👁</span><span class="entn mono">'+esc(e.entity)+'</span>'+(e.note?'<span class="wnote" title="'+esc(e.note)+'">'+esc((e.note+"").slice(0,42))+'</span>':'')+'<span class="entn2 mono">'+esc((e.ts||"").slice(0,10))+'</span></div>').join("")):"";
  }).catch(()=>{});}
function openWatch(i){var e=WATCHL[i];if(e)openEntity(e.entity,((e.entity||"")+"").split("\\").pop());}
function toggleWatch(){var who=(ENT_CUR&&(ENT_CUR.full||ENT_CUR.label));if(!who)return;
  fetch(API+"/watch",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({entity:who,action:"toggle"})}).then(r=>r.json()).then(r=>{
    var b=$("#watchBtn");if(b){b.className="watchbtn"+(r.watched?" on":"");var sp=b.querySelector("span");if(sp)sp.textContent=r.watched?t("watch_on"):t("watch_off");}
    toast(r.watched?t("watch_added"):t("watch_removed"),"ok");loadWatchlist();
  }).catch(()=>{});}
function rkChip(r){if(!r||r.score==null)return '';var c=r.score>=80?"rk-c":r.score>=60?"rk-h":r.score>=35?"rk-m":"rk-l";
  return '<span class="rkchip '+c+'" title="'+t("risk_"+(r.label||"minimal"))+' — '+t("risk_fused")+'">'+r.score+'</span>';}
function entRow(e,k,i){return '<div class="entrow" data-onclick="openEntB(\''+k+'\','+i+')">'+rkChip(e.risk)+'<span class="entk">'+(k==='m'?ic("cpu"):'👤')+'</span><span class="entn mono">'+esc(e.entity)+(e.watched?' <span class="weye" title="'+t("watch_on")+'">👁</span>':'')+'</span><span class="entn2 mono">'+((e.n||0).toLocaleString('fr'))+'</span></div>';}
function openEntB(k,i){const e=(k==='m'?ENTB.machines:ENTB.users)[i];if(e)openEntity(e.entity,((e.entity||"")+"").split("\\").pop());}
function openEntS(i){const e=ENTS[i];if(e)openEntity(e.entity,((e.entity||"")+"").split("\\").pop());}
function entSearchDo(q){q=(q||"").trim();const r=$("#entResults");if(!r)return;
  if(q.length<2){r.innerHTML="";return;}
  j("/entity-search?q="+encodeURIComponent(q)).then(d=>{ENTS=d.results||[];
    r.innerHTML=ENTS.length?'<div class="lbl2">'+t("ent_res")+'</div>'+ENTS.map((e,i)=>'<div class="entrow" data-onclick="openEntS('+i+')"><span class="entk">'+(e.kind==='host'?ic("cpu"):'👤')+'</span><span class="entn mono">'+esc(e.entity)+'</span><span class="entn2 mono">'+(e.n||0).toLocaleString('fr')+' '+t("pal_evts")+'</span></div>').join(""):'<div class="muted gpad">'+t("ent_nores")+'</div>';
  }).catch(()=>{});}
// --- Chronologie unifiée (timeline d'entité, dans le dossier) ---
function loadTimeline(who){const w=$("#tlWrap");if(!w)return;w.innerHTML="";
  fetch(API+"/entity-timeline?u="+encodeURIComponent(who)+"&days=14",{credentials:"same-origin"}).then(r=>r.json()).then(d=>renderTimeline(w,d)).catch(()=>{});}
function renderTimeline(w,d){const items=(d&&d.items)||[];if(!w)return;if(!items.length){w.innerHTML="";return;}
  const row=x=>{let icon,cls,txt;
    if(x.kind==="detection"){cls="tl-"+(x.sev?sevClass(x.sev):"medium");icon=ic("warning");txt='<b>'+nice(x.label)+'</b> '+(x.tech?'<span class="srcb">'+esc(x.tech)+'</span>':'')+(x.src?'<span class="src">'+esc(x.src)+'</span>':'');}
    else if(x.kind==="m365"){cls=x.ok?"tl-ok":"tl-high";icon=ic("globe");txt='<b>M365</b> '+(x.ok?'<span style="color:var(--grn)">'+t("tl_ok")+'</span>':'<span style="color:#f5a623">'+esc(x.detail||codeLabel(x.code))+'</span>')+' '+(x.ip?'<span class="mono">'+esc(x.ip)+'</span> '+(x.cc?flagOf(x.cc):''):'');}
    else {cls="tl-high";icon=ic("alert");txt='<b>Windows</b> <span style="color:#f5a623">'+t("tl_fail")+'</span> '+(x.ip?'<span class="mono">'+esc(x.ip)+'</span>':'');}
    return '<div class="tlrow '+cls+'"><span class="tlt">'+ago(x.ts)+'</span><span class="tli">'+icon+'</span><span class="tlx">'+txt+'</span></div>';};
  w.innerHTML='<div class="blk"><div class="lbl">'+ic("bars")+' '+t("tl_title")+' <span class="muted" style="font-weight:400">'+t("tl_sub")+'</span></div><div class="tl">'+items.map(row).join("")+'</div></div>';}
function renderSentinelPosture(d){const c=$("#sentinelCard"),b=$("#sentinelBody");if(!c||!b||!d||d.error)return;
  const EN=LANG==="en";const jx=d.jewel_exposure||[];const minh=jx.length?jx[0].min_hops:null;
  const spof=(d.single_points_of_failure||[]).length;const chk=(d.chokepoints||[]).length;
  const tile=(v,l,col)=>'<div class="kpi '+(col||'cy')+'"><div class="lab">'+l+'</div><div class="val mono">'+v+'</div></div>';
  b.innerHTML=tile(jx.length,(EN?"jewels exposed":"joyaux exposés"),jx.length?'red':'cy')
    +tile(minh==null?'—':'≤'+minh,(EN?"hops to nearest":"sauts au + proche"),(minh!=null&&minh<=3)?'red':'amb')
    +tile(chk,(EN?"chokepoints":"chokepoints"),'amb')
    +tile(spof,(EN?"single points":"points uniques"),spof?'red':'cy');
  c.style.display="block";}
function renderRisk(d){d=d||{};
  const M={CRITIQUE:["red","Compromission probable — action immédiate"],ELEVE:["amb","Activité critique en cours"],SURVEILLE:["blu","Signaux à surveiller"],NOMINAL:["grn","Aucune menace active"]};
  const m=M[d.threat_level]||M.NOMINAL;const t=$("#threat");
  if(t){t.className="threat "+m[0];$("#tlabel").textContent=d.threat_level||"NOMINAL";$("#tsub").textContent="Niveau de menace · "+m[1];
    // Pas de doublon des KPI (deja dans la rangee canonique) : on pointe l'entite prioritaire.
    const te=(d.top_entities||[])[0];
    $("#tstats").innerHTML=te?`<div style="font-size:12px;color:var(--mut);align-self:center;white-space:nowrap">${(LANG==="en")?"Priority watch":"À surveiller"} · <b style="color:var(--fg)" class="mono">${esc(((te.k||"")+"").split("\\").pop())}</b></div>`:"";}
  TOPE=d.top_entities||[];
  $("#topEnt").innerHTML=TOPE.length?TOPE.map((e,i)=>{const who=((e.k||"")+"").split("\\").pop();
    return `<div class="inc" data-onclick="openTopE(${i})"><div class="top">${rkChip(e.risk)}<span class="ttl">👤 ${esc(who)}${e.watched?' <span class="weye" title="'+t("watch_on")+'">👁</span>':''}</span>
      <span class="ts" style="margin-left:auto">${(e.n||0).toLocaleString("fr")} dét. · ${e.tech||0} tech.</span></div></div>`;}).join(""):'<div class="empty">—</div>';
  const sevc=s=>s>=85?'var(--red)':s>=70?'var(--amb)':s>=40?'var(--blu)':'var(--grn)';
  MLT=d.ml_top||[];
  $("#mlTop").innerHTML=MLT.length?MLT.map((m,i)=>{const ic=m.type==='host'?'🖥️':'👤';
    return `<div class="inc" data-onclick="openMl(${i})"><div class="top"><span class="ttl">${ic} ${esc(m.entity)}</span>
      <span class="mono" style="color:${sevc(m.score)};margin-left:auto;font-weight:700">${m.score}</span></div>
      <div class="ts" style="white-space:normal;color:var(--mut)">${esc(m.reason||"")}</div></div>`;}).join(""):'<div class="empty">'+t("empty_ml")+'</div>';
  const UB=d.ueba_top||[];
  $("#uebaTop").innerHTML=UB.length?UB.map(u=>`<div class="inc"><div class="top"><span class="ttl">📍 ${esc(u.entity)}</span>
      <span class="mono" style="color:${sevc(u.score)};margin-left:auto;font-weight:700">${u.score}</span><span class="ts">${esc(u.factor||"")}</span></div></div>`).join(""):'<div class="empty">'+t("empty_ueba")+'</div>';}
function openTopE(i){const e=TOPE[i];if(e&&e.k)openEntity(e.k,((e.k||"")+"").split("\\").pop());}
function openMl(i){const m=MLT[i];if(m&&m.entity)openEntity(m.entity,((m.entity||"")+"").split("\\").pop());}
function flagOf(cc){return (cc&&cc.length===2)?cc.toUpperCase().replace(/./g,ch=>String.fromCodePoint(127397+ch.charCodeAt(0))):"🏳️";}
function renderGeo(d){d=d||{};const cs=d.countries||[];const max=cs.length?cs[0].n:1;
  $("#geoFeed").innerHTML=cs.length?cs.map(c=>`<div class="georow"><span class="gflag">${flagOf(c.k)}</span><span class="gcc">${esc(c.k)}</span>
    <div class="gbar"><div style="width:${Math.max(3,Math.round(c.n/max*100))}%"></div></div>
    <span class="gn mono">${(c.n||0).toLocaleString("fr")}</span></div>`).join(""):'<div class="empty">'+t("empty_geo")+'</div>';}
function renderKpis(k){k=k||{};
  $("#kpis").innerHTML=[
    ["red",ic("warning"),"Incidents critiques (7 j)",k.incidents_critiques_7j,"corrélés oms-xdr","incidents"],
    ["amb",ic("target"),"Hôtes à risque (UEBA)",k.hotes_risque_ueba,"score ≥ 80","graph"],
    ["cy",ic("antenna"),"Événements détectés (24 h)",k.alertes_24h,"détections taguées","detections"],
    ["vio",ic("shield"),"CVE KEV exposées",k.kev_exposees,"catalogue CISA","detections"]
  ].map(([c,i,l,v,s,p])=>`<div class="kpi ${c}" style="cursor:pointer" data-onclick="goNav('${p}')"><div class="lab">${i} ${l}</div>
    <div class="val mono">${(v??0).toLocaleString("fr")}</div><div class="sub">${s}</div></div>`).join("");
}
function renderTs(s){s=s||[];const lab=s.map(x=>new Date(x.t).getHours()+"h"),d=s.map(x=>x.n);
  mk("cTs",{type:"line",data:{labels:lab,datasets:[{data:d,borderColor:"#22d3ee",borderWidth:2,
    fill:true,tension:.35,pointRadius:0,backgroundColor:c=>{const g=c.chart.ctx.createLinearGradient(0,0,0,240);
      g.addColorStop(0,"rgba(34,211,238,.35)");g.addColorStop(1,"rgba(34,211,238,0)");return g;}}]},
    options:{...noLeg,maintainAspectRatio:false,scales:{x:{grid:{display:false}},y:{beginAtZero:true}}}});
}
function donut(id,data){const d=data||[];mk(id,{type:"doughnut",
  data:{labels:d.map(x=>nice(x.k)),datasets:[{data:d.map(x=>x.n),backgroundColor:PAL,borderColor:"#0d1424",borderWidth:2}]},
  options:{maintainAspectRatio:false,cutout:"62%",plugins:{legend:{position:"right",labels:{boxWidth:10,font:{size:11}}}}}});}
function renderTac(d){donut("cTac",d);}
function renderSrc(d){donut("cSrc",d);}
function renderDet(d){d=d||[];mk("cDet",{type:"bar",
  data:{labels:d.map(x=>nice(x.k)),datasets:[{data:d.map(x=>x.n),backgroundColor:"#a78bfa",borderRadius:5}]},
  options:{...noLeg,indexAxis:"y",maintainAspectRatio:false,scales:{x:{beginAtZero:true},y:{grid:{display:false}}}}});}
let cy=null,GRAPH=null;
const GCFG={name:"cose",animate:false,padding:30,nodeRepulsion:9000,idealEdgeLength:95,nodeOverlap:14};
function renderGraph(d){GRAPH=d||{nodes:[],edges:[]};buildGraph();}
function renderTwin(d){
  const w=$("#twinWrap");if(!w)return;d=d||{};
  const EN=LANG==="en";
  const T=EN?{una:"Attack twin unavailable",hint:"run 89-attack-graph.sh, then the daily oms-graph timer.",
    gen:"generated",win:"window",hosts:"hosts",accts:"accounts",jewels:"jewels",foot:"footholds",
    jx:"Crown-jewel exposure",jxs:"foothold → jewel, in N hops (fewer = more exposed)",
    nopath:"No jewel reachable from a foothold — good news.",hops:"hops",from:"from",foots:"foothold(s)",eg:"e.g.",
    cp:"Chokepoints — harden / place a decoy here first",onp:"paths",
    blast:"Blast radius — if compromised, hosts reachable",reach:"hosts",
    spof:"Single points of failure (management accounts admin everywhere)",adminon:"hosts admin",pam:"→ PAM + tiering",
    reco:"Recommended decoy placement (feeds the deception layer)",toplace:"TO PLACE",cov:"already covered",on:"on",near:"near",
    paths:"Sample exposure paths"}:
   {una:"Jumeau d'attaque indisponible",hint:"lancer 89-attack-graph.sh, puis le timer quotidien oms-graph.",
    gen:"généré",win:"fenêtre",hosts:"hôtes",accts:"comptes",jewels:"joyaux",foot:"pieds-à-terre",
    jx:"Exposition des joyaux",jxs:"pied-à-terre → joyau, en N sauts (moins = plus exposé)",
    nopath:"Aucun joyau atteignable depuis un pied-à-terre — bonne nouvelle.",hops:"sauts",from:"depuis",foots:"pied(s)-à-terre",eg:"ex",
    cp:"Chokepoints — durcir / poser un leurre en priorité",onp:"chemins",
    blast:"Rayon de souffle — si compromis, hôtes atteignables",reach:"hôtes",
    spof:"Points uniques catastrophiques (comptes de gestion admin partout)",adminon:"hôtes admin",pam:"→ PAM + tiering",
    reco:"Placement de leurres recommandé (alimente la déception)",toplace:"À POSER",cov:"déjà couvert",on:"sur",near:"près de",
    paths:"Échantillon de chemins d'exposition"};
  if(d.error){w.innerHTML='<div class="card"><h3><svg class="svi"><use href="#i-target"></use></svg> '+T.una+'</h3><p class="muted">'+esc(d.hint||T.hint)+'</p></div>';return;}
  const s=d.stats||{};const kl=k=>k==="privileged"?"#fb3b53":k==="management"?"#f5a623":k==="host"?"#38bdf8":"#9aa7bd";
  const hc=h=>h<=2?"#fb3b53":h<=4?"#f5a623":"#2563eb";
  const K=(v,l)=>'<div class="kpi cy"><div class="lab">'+l+'</div><div class="val mono">'+(v==null?0:v).toLocaleString("fr")+'</div></div>';
  let H='';
  H+='<div class="card"><h3><svg class="svi"><use href="#i-target"></use></svg> '+(EN?"Attack twin":"Jumeau d'attaque")+
     '<span class="tag">oms-graph · '+esc(d.window||"")+'</span></h3>'+
     '<div class="mono muted" style="font-size:12px;margin-bottom:8px">'+T.gen+' '+esc((d.generated_at||"").replace("T"," ").replace("Z"," UTC"))+'</div>'+
     '<div class="grid kpis">'+
       K(s.hosts,T.hosts)+K(s.accounts,T.accts)+K(s.jewels,T.jewels)+K(s.footholds,T.foot)+
     '</div></div>';
  // Exposition des joyaux
  H+='<div class="card"><h3><svg class="svi"><use href="#i-alert"></use></svg> '+T.jx+'<span class="tag">'+T.jxs+'</span></h3>';
  const jx=d.jewel_exposure||[];
  if(!jx.length){H+='<p class="muted">'+T.nopath+'</p>';}
  else{H+='<div class="feed">'+jx.map(j=>'<div class="frow" data-onclick="simResponse(\''+_jsq(j.nearest_foothold||"")+'\')" title="'+(EN?"Response on nearest foothold":"Réponse sur le pied-à-terre le plus proche")+'" style="cursor:pointer;display:flex;align-items:center;gap:12px">'+
    '<span class="pill mono" style="background:'+hc(j.min_hops)+'22;border-color:'+hc(j.min_hops)+'66;color:'+hc(j.min_hops)+'">≤'+j.min_hops+' '+T.hops+'</span>'+
    '<b style="flex:1">'+esc(j.label||j.jewel)+'</b>'+
    '<span class="muted" style="font-size:12px">'+T.from+' '+j.reachable_from+' '+T.foots+' · '+T.eg+' '+esc(j.nearest_foothold||"")+'</span></div>').join('')+'</div>';}
  H+='</div>';
  // Chokepoints + Blast radius (deux colonnes)
  H+='<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(320px,1fr))">';
  const cp=d.chokepoints||[];const cmax=cp.length?cp[0].on_paths:1;
  H+='<div class="card"><h3>'+T.cp+'<span class="tag">'+(EN?"click → graded response":"clic → réponse graduée")+'</span></h3><div class="feed">'+cp.map(c=>
    '<div class="frow" data-onclick="simResponse(\''+_jsq(c.entity)+'\')" title="'+(EN?"Simulate response":"Simuler la réponse")+'" style="cursor:pointer;display:flex;align-items:center;gap:10px"><span class="mono" style="color:'+kl(c.klass)+';min-width:34px;text-align:right">'+c.on_paths+'</span>'+
    '<span style="flex:1"><span class="bar" style="display:inline-block;height:7px;border-radius:4px;background:'+kl(c.klass)+';width:'+Math.max(8,Math.round(100*c.on_paths/cmax))+'%"></span> '+esc(c.entity)+'</span>'+
    '<span class="tag" style="font-size:10px">'+esc(c.klass)+'</span></div>').join('')+'</div></div>';
  const bl=d.blast_radius||[];const bmax=bl.length?bl[0].hosts_reached:1;
  H+='<div class="card"><h3>'+T.blast+'<span class="tag">'+(EN?"click → graded response":"clic → réponse graduée")+'</span></h3><div class="feed">'+bl.map(b=>
    '<div class="frow" data-onclick="simResponse(\''+_jsq(b.entity)+'\')" title="'+(EN?"Simulate response":"Simuler la réponse")+'" style="cursor:pointer;display:flex;align-items:center;gap:10px"><span class="mono" style="color:'+kl(b.klass)+';min-width:34px;text-align:right">'+b.hosts_reached+'</span>'+
    '<span style="flex:1"><span class="bar" style="display:inline-block;height:7px;border-radius:4px;background:'+kl(b.klass)+';width:'+Math.max(8,Math.round(100*b.hosts_reached/bmax))+'%"></span> '+esc(b.entity)+
    (b.jewels_reached&&b.jewels_reached.length?' <span class="tag" style="font-size:10px;color:#fb3b53">'+b.jewels_reached.length+' '+T.jewels+'</span>':'')+'</span></div>').join('')+'</div></div>';
  H+='</div>';
  // Points uniques
  const sp=d.single_points_of_failure||[];
  if(sp.length){H+='<div class="card"><h3 style="color:#fb3b53"><svg class="svi"><use href="#i-unlock"></use></svg> '+T.spof+'</h3><div class="feed">'+
    sp.map(p=>'<div class="frow" style="display:flex;align-items:center;gap:12px"><span class="pill mono" style="background:#fb3b5322;border-color:#fb3b5366;color:#fb3b53">'+p.admin_on_hosts+' '+T.adminon+'</span><b style="flex:1">'+esc(p.account)+'</b><span class="muted" style="font-size:12px">'+T.pam+'</span></div>').join('')+'</div></div>';}
  // Recommandations de leurres
  const rc=d.decoy_recommendations||[];
  if(rc.length){H+='<div class="card"><h3><svg class="svi"><use href="#i-target"></use></svg> '+T.reco+'</h3><div class="feed">'+
    rc.map(r=>{const loc=r.place_on_host||r.near_jewel||"";const where=r.place_on_host?T.on:T.near;
      return '<div class="frow" style="display:flex;align-items:center;gap:10px">'+
      '<span class="pill" style="font-size:10px;'+(r.already_covered?'background:#10233a;color:#9aa7bd':'background:#2a1f10;border-color:#f5a62366;color:#f5a623')+'">'+(r.already_covered?T.cov:T.toplace)+'</span>'+
      '<span class="mono" style="flex:1">'+esc(r.type)+" '"+esc(r.suggested_key)+"' "+where+' '+esc(loc)+'</span></div>';}).join('')+'</div></div>';}
  // Chemins (échantillon)
  const pp=d.attack_paths||[];
  if(pp.length){H+='<div class="card"><h3>'+T.paths+'</h3><div class="feed">'+pp.map(p=>
    '<div class="frow mono" style="font-size:12px"><span class="pill" style="background:'+hc(p.hops)+'22;border-color:'+hc(p.hops)+'66;color:'+hc(p.hops)+'">'+p.hops+' '+T.hops+'</span> '+
    (p.path||[]).map((n,i)=>'<span style="color:'+(p.path_kinds&&p.path_kinds[i]==="host"?"#38bdf8":"#9aa7bd")+'">'+esc(n)+'</span>').join(' <span class="muted">→</span> ')+'</div>').join('')+'</div></div>';}
  // Exposition de données (Kerberos) : qui peut ATTEINDRE chaque joyau (≠ contrôle).
  const de=d.data_exposure||[];
  if(de.length){H+='<div class="card"><h3>'+(EN?"Data exposure (Kerberos → jewels)":"Exposition de données (Kerberos → joyaux)")+'<span class="tag">'+(EN?"who can access — least privilege":"qui accède — moindre privilège")+'</span></h3><div class="feed">';
    de.forEach(x=>{const routine=x.count>30;
      H+='<div class="frow" style="padding:8px 0"><div style="display:flex;align-items:center;gap:10px"><span class="pill mono" style="min-width:34px;text-align:center;'+(routine?'background:#10233a;color:#9aa7bd':'background:#2a1f10;border-color:#f5a62366;color:#f5a623')+'">'+x.count+'</span><b style="flex:1">'+esc(x.label)+'</b>'+(routine?'<span class="muted" style="font-size:11px">'+(EN?"routine (all auth here)":"routine (tous y authentifient)")+'</span>':'')+'</div>';
      if(!routine){H+='<div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:5px">'+(x.accounts||[]).map(a=>'<span class="pchip" data-onclick="openEntity(\''+_jsq(a)+'\',\''+_jsq(a)+'\')" title="'+(EN?"Open dossier":"Ouvrir le dossier")+'" style="cursor:pointer">'+esc(a)+'</span>').join('')+(x.truncated?' <span class="muted">…</span>':'')+'</div>';}
      H+='</div>';});
    H+='</div></div>';}
  w.innerHTML=H;
}
function _jsq(s){return (s==null?"":""+s).replace(/[\\']/g,"\\$&");}
function simClose(EN,ent){return '<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px">'
  +(ent?'<button class="stb" data-onclick="simToDossier(\''+_jsq(ent)+'\')">'+(EN?"360° dossier":"Dossier 360°")+'</button>':'')
  +'<button class="stb" data-onclick="closeSim()">'+(EN?"Close":"Fermer")+'</button></div>';}
function simToDossier(ent){closeSim();openEntity(ent,((ent||"")+"").split("\\").pop());}
function closeSim(){var m=$("#simModal");if(m)m.style.display="none";}
function simResponse(ent){if(!ent)return;const EN=LANG==="en";const M=$("#simBody");if(!M)return;
  $("#simModal").style.display="block";
  M.innerHTML='<p class="muted">'+(EN?"Computing graded response…":"Calcul de la réponse graduée…")+'</p>';
  j("/sentinel-sim?entity="+encodeURIComponent(ent)).then(d=>{
    if(!d||d.error){M.innerHTML='<h3>'+esc(ent)+'</h3><p class="muted">'+esc((d&&d.error)||"?")+'</p>'+simClose(EN,ent);return;}
    const gc={critique:"#fb3b53",eleve:"#f5a623",modere:"#9aa7bd"}[d.grade]||"#9aa7bd";
    const gl=EN?{critique:"CRITICAL",eleve:"HIGH",modere:"MODERATE"}:{critique:"CRITIQUE",eleve:"ÉLEVÉ",modere:"MODÉRÉ"};
    const jr=d.jewels_at_risk||[];
    let h='<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px"><span class="pill" style="background:'+gc+'22;border-color:'+gc+'66;color:'+gc+';font-weight:700">'+(gl[d.grade]||d.grade)+'</span><h3 style="margin:0">'+esc(ent)+'</h3></div>';
    h+='<div class="muted" style="font-size:12px;margin-bottom:8px">'+(EN?"Hypothetical compromise (tabletop)":"Compromission hypothétique (tabletop)")+' · '+(d.hosts_reachable||0)+' '+(EN?"hosts reachable":"hôtes atteignables")+(jr.length?' · '+(EN?"jewels at risk":"joyaux menacés")+': '+jr.map(esc).join(", "):"")+'</div>';
    h+='<div class="muted" style="font-size:11px;margin-bottom:10px;padding:6px 9px;background:#0a1322;border-radius:8px">Mode: <b style="color:'+(d.mode==="armed"?"#fb3b53":"#38bdf8")+'">'+(d.mode==="armed"?(EN?"ARMED":"ARMÉ"):"DRY-RUN")+'</b> — '+(EN?"recommendations until you arm + approve on the host":"recommandations tant que non armé + approuvé sur l'hôte")+'</div>';
    h+=(d.steps||[]).map(s=>'<div style="display:flex;gap:10px;padding:9px 0;border-top:1px solid var(--bd)"><span class="mono" style="color:'+gc+';min-width:140px">'+esc(s.action)+'</span><span style="flex:1;font-size:13px">'+esc(s.text)+'</span></div>').join("");
    h+=simClose(EN,ent);M.innerHTML=h;
  }).catch(()=>{M.innerHTML='<p class="muted">'+(EN?"Unavailable":"Indisponible")+'</p>'+simClose(EN,ent);});}
function buildGraph(){buildGraphView(GRAPH);}
function buildGraphView(view){
  if(!window.cytoscape||!$("#cy")||!view)return;
  if(cy){cy.destroy();cy=null;}
  cy=cytoscape({container:$("#cy"),
    elements:[...(view.nodes||[]).map(n=>({data:{...n,color:n.type==="technique"?(TACCOL[n.tactic]||"#a78bfa"):"#22d3ee"}})),...(view.edges||[]).map(e=>({data:e}))],
    style:[
      {selector:'node[type="entity"]',style:{'background-color':'#22d3ee','label':'data(label)','color':'#cde8f2','font-size':11,'font-weight':'bold','width':'mapData(weight,0,4000,26,52)','height':'mapData(weight,0,4000,26,52)','text-valign':'bottom','text-margin-y':3,'border-width':2,'border-color':'#0e7490'}},
      {selector:'node[type="technique"]',style:{'background-color':'data(color)','shape':'round-diamond','label':'data(label)','color':'#cdd6e6','font-size':9,'width':24,'height':24,'text-valign':'bottom','text-margin-y':2}},
      {selector:'edge',style:{'width':'mapData(weight,0,3000,1,7)','line-color':'data(color)','line-color':'#2b3a55','target-arrow-shape':'triangle','target-arrow-color':'#2b3a55','curve-style':'bezier','opacity':.7}},
      {selector:'node:selected',style:{'border-width':3,'border-color':'#fff'}},
      {selector:'.gdim',style:{'opacity':.12}},
      {selector:'.ghit',style:{'border-width':4,'border-color':'#f5a623','opacity':1}}
    ],layout:GCFG});
  cy.on('tap','node[type="entity"]',e=>openEntity(e.target.data('full'),e.target.data('label')));
}
function openEntity(full,label,size){
  size=size||20;ENT_CUR={full:full,label:label};ENT_SIZE=size;
  // Ouverture IMMEDIATE avec placeholder (evite l'attente + l'affichage de donnees perimees)
  $("#emc").innerHTML='<div class="grip"></div><p class="muted" style="padding:28px 0;text-align:center">'+((LANG==="en")?"Loading dossier ":"Chargement du dossier ")+esc(label||"")+'…</p>';
  $("#emodal").classList.add("on");
  fetch(API+"/entity?u="+encodeURIComponent(full||label)+"&size="+size,{credentials:"same-origin"}).then(r=>r.json()).then(d=>{
    const techs=(d.techniques||[]).map(t=>`<span class="pchip">${esc(t.k)} · ${t.n}</span>`).join(" ")||'<span class="muted">—</span>';
    const tacs=(d.tactics||[]).map(t=>`<span class="pchip tac">${esc(t.k)}</span>`).join(" ");
    const evs=(d.events||[]).map(e=>`<div class="erow"><span class="ts">${ago(e.ts)}</span> <b>${nice(e.tag)}</b> <em>${esc(e.tech||"")}</em><div class="emsg">${esc((e.msg||"").slice(0,150))}</div></div>`).join("")||'<div class="muted">'+t("empty_event")+'</div>';
    const loaded=(d.events||[]).length;
    const more=d.has_more?`<button class="entMore" data-onclick="entMore()">${t("load_more")} (${loaded} / ${(d.total||0).toLocaleString("fr")})</button>`:(loaded>20?`<div class="muted" style="text-align:center;margin-top:8px;font-size:11px">${loaded} ${t("events_shown")}</div>`:'');
    $("#emc").innerHTML=`<div class="grip"></div>
      <div class="ehd"><h2>👤 ${esc(label)}</h2><button class="watchbtn${d.watched?' on':''}" id="watchBtn" data-onclick="toggleWatch()" title="${t("watch_hint")}">👁 <span>${d.watched?t("watch_on"):t("watch_off")}</span></button></div>
      <div class="muted" style="margin-bottom:4px">${esc(full||"")} · <b style="color:var(--cy)">${(d.total||0).toLocaleString("fr")}</b> ${t("ent_detn")}</div>
      ${(d.linked&&d.linked.length>1)?`<div class="idu"><span class="idulb">${ic("network")} ${t("id_unified").replace("{n}",d.linked.length)}</span> ${d.linked.map(a=>`<span class="idchip">${esc(a)}</span>`).join("")}</div>`:''}
      ${entScoreBanner(d)}
      <div id="expWrap"></div>
      <div id="emsEntWrap"></div>
      <div id="netEntWrap"></div>
      <div id="invWrap"></div>
      <div id="tlWrap"></div>
      <div class="blk"><div class="lbl">${t("ent_tactics")}</div><div>${tacs}</div></div>
      <div class="blk"><div class="lbl">${t("ent_techniques")}</div><div>${techs}</div></div>
      <div class="blk"><div class="lbl">${t("ent_events")}</div>${evs}${more}</div>`;
    $("#emodal").classList.add("on");
    loadInvestigation(full||label);loadTimeline(full||label);loadExposure(full||label);loadEntityEms(full||label);loadEntityNetwork(full||label);
  }).catch(()=>{});
}
function loadEntityNetwork(u){const w=$("#netEntWrap");if(!w)return;w.innerHTML="";
  j("/entity-network?u="+encodeURIComponent(u)).then(d=>{if(!d||!d.found)return;const EN=LANG==="en";
    const hasSec=(d.tags||[]).length>0;const col=hasSec?"#f5a623":"#38bdf8";
    let h='<div class="blk" style="border:1px solid '+col+'44;border-radius:10px;padding:10px 12px;background:'+col+'0d">'
      +'<div class="lbl" style="display:flex;align-items:center;gap:8px">'+ic("network")+' '+(EN?"Network / infra activity":"Activité réseau / infra")
      +'<span class="muted" style="margin-left:auto;font-size:11px">'+(d.total||0)+' '+(EN?"events / 14d":"events / 14j")+'</span></div>'
      +'<div style="font-size:13px;margin-top:6px">';
    (d.sources||[]).forEach(s=>{h+='<span class="pchip">'+esc(s.k)+' · '+s.n+'</span> ';});
    (d.tags||[]).forEach(x=>{h+='<span class="pchip" style="color:'+col+'">'+nice(x.k)+' · '+x.n+'</span> ';});
    h+='</div>';
    const ev=(d.events||[]).slice(0,4);
    if(ev.length)h+='<div style="margin-top:6px">'+ev.map(e=>'<div class="muted" style="font-size:11px;border-top:1px solid var(--bd);padding-top:4px;margin-top:4px">'+(e.tag?'<b style="color:'+col+'">'+nice(e.tag)+'</b> · ':'')+(e.host?esc(e.host)+' · ':'')+(e.ip?esc(e.ip)+' · ':'')+(e.seg?'<span style="color:var(--cy)">'+esc(e.seg)+'</span> · ':'')+esc((e.msg||'').slice(0,80))+'</div>').join('')+'</div>';
    h+='</div>';w.innerHTML=h;
  }).catch(()=>{});}
function loadEntityEms(u){const w=$("#emsEntWrap");if(!w)return;w.innerHTML="";
  j("/entity-ems?u="+encodeURIComponent(u)).then(d=>{if(!d||!d.found)return;const EN=LANG==="en";
    const crit=(d.malware||d.av_off);const col=crit?"#fb3b53":(d.vuln?"#f5a623":"#38bdf8");
    let h='<div class="blk" style="border:1px solid '+col+'44;border-radius:10px;padding:10px 12px;background:'+col+'0d">'
      +'<div class="lbl" style="display:flex;align-items:center;gap:8px">'+ic("cpu")+' '+(EN?"Endpoint state (FortiClient EMS)":"État endpoint (FortiClient EMS)")
      +'<span class="muted" style="margin-left:auto;font-size:11px">'+(d.total||0)+' '+(EN?"events / 30d":"events / 30j")+'</span></div>'
      +'<div style="font-size:13px;margin-top:6px">';
    if(d.malware)h+='<span class="pchip" style="color:#fb3b53">'+d.malware+' '+(EN?"malware":"malware")+'</span> ';
    if(d.av_off)h+='<span class="pchip" style="color:#fb3b53">'+(EN?"protection off":"protection désactivée")+'</span> ';
    if(d.vuln)h+='<span class="pchip" style="color:#f5a623">'+d.vuln+' '+(EN?"critical vuln":"vuln. critiques")+'</span> ';
    if(!d.malware&&!d.av_off&&!d.vuln)h+='<span class="muted">'+(EN?"reporting, no security event":"remonte, aucun event sécurité")+'</span>';
    h+='</div>';
    const ev=(d.events||[]).filter(e=>e.tag).slice(0,3);
    if(ev.length)h+='<div style="margin-top:6px">'+ev.map(e=>'<div class="muted" style="font-size:11px;border-top:1px solid var(--bd);padding-top:4px;margin-top:4px"><b style="color:'+col+'">'+nice(e.tag)+'</b>'+(e.threat?' · '+esc(e.threat):'')+' · '+esc((e.msg||'').slice(0,80))+'</div>').join('')+'</div>';
    h+='</div>';w.innerHTML=h;
  }).catch(()=>{});}
function loadExposure(u){const w=$("#expWrap");if(!w)return;w.innerHTML="";
  j("/entity-exposure?u="+encodeURIComponent(u)).then(d=>{if(!d||!d.found){return;}
    const EN=LANG==="en";const jr=d.jewels_reached||[];
    const crit=jr.length>0;const col=crit?"#fb3b53":(d.is_chokepoint?"#f5a623":"#38bdf8");
    let h='<div class="blk" style="border:1px solid '+col+'44;border-radius:10px;padding:10px 12px;background:'+col+'0d">'
      +'<div class="lbl" style="display:flex;align-items:center;gap:8px">'+ic("target")+' '+(EN?"Attack-twin exposure":"Exposition (jumeau d'attaque)")
      +'<button class="stb" style="margin-left:auto" data-onclick="simResponse(\''+_jsq(d.entity)+'\')">'+(EN?"Simulate response":"Simuler la réponse")+'</button></div>'
      +'<div style="font-size:13px;margin-top:6px">';
    if(d.is_chokepoint)h+='<span class="pchip" style="color:#f5a623">'+(EN?"Chokepoint":"Chokepoint")+' · '+d.on_paths+' '+(EN?"paths":"chemins")+'</span> ';
    h+='<span class="pchip">'+(d.hosts_reached||0)+' '+(EN?"hosts reachable":"hôtes atteignables")+'</span> ';
    if(jr.length)h+='<span class="pchip" style="color:#fb3b53">'+(EN?"reaches: ":"atteint : ")+jr.map(esc).join(", ")+'</span>';
    h+='</div></div>';w.innerHTML=h;
  }).catch(()=>{});}
const M365CODE={
 fr:{"0":"Succès","50053":"Compte verrouillé (lockout)","50055":"Mot de passe expiré","50057":"Compte désactivé","50074":"MFA requise","50076":"MFA requise (CA)","50079":"MFA à enregistrer","50126":"Identifiants invalides","50158":"Conditional Access","53003":"Bloqué (Conditional Access)","500121":"MFA refusée / timeout"},
 en:{"0":"Success","50053":"Account locked (lockout)","50055":"Password expired","50057":"Account disabled","50074":"MFA required","50076":"MFA required (CA)","50079":"MFA registration required","50126":"Invalid credentials","50158":"Conditional Access","53003":"Blocked (Conditional Access)","500121":"MFA denied / timeout"}};
function codeLabel(c){return (M365CODE[LANG]||M365CODE.fr)[String(c)]||("code "+esc(String(c)));}
function loadInvestigation(who){const w=$("#invWrap");if(!w)return;
  w.innerHTML=`<div class="blk inv"><div class="lbl">${ic("globe")} ${t("inv_title")}</div><div class="muted">${t("inv_analyzing")}</div></div>`;
  fetch(API+"/investigate?u="+encodeURIComponent(who)+"&days=14",{credentials:"same-origin"})
    .then(r=>r.json()).then(renderInvestigation).catch(()=>{});}
const LTYPE={"2":"Interactive","3":"Network","4":"Batch","5":"Service","7":"Unlock","8":"NetworkCleartext","9":"NewCredentials","10":"RDP","11":"CachedInteractive"};
function ltype(k){return (LTYPE[String(k)]||"type")+" ("+esc(String(k))+")";}
const FAILR_EN={"restriction_compte":"account restriction","utilisateur_inexistant":"unknown user","mot_de_passe_errone":"wrong password","compte_verrouille":"account locked","compte_desactive":"account disabled","desynchronisation_horloge":"clock skew","mot_de_passe_expire":"password expired","erreur_pendant_logon":"logon error"};
function niceReason(s){const k=String(s||"");if(LANG==="en"&&FAILR_EN[k])return esc(FAILR_EN[k]);return esc(k.replace(/_/g," "));}
function renderInvestigation(d){const w=$("#invWrap");if(!w||!d)return;
  const a=d.auth||{},wn=d.winauth||{},det=d.detections||[],src=d.sources||[];const daySuffix=(LANG==="en"?"d":"j");let h='';
  if(a.total){const cs=a.countries||[],cmax=cs.length?cs[0].n:1;
    h+=`<div class="invk">
      <div class="ik"><div class="ikv mono">${(a.total||0).toLocaleString("fr")}</div><div class="iks">${t("k_attempts")}</div></div>
      <div class="ik ok"><div class="ikv mono">${(a.success||0).toLocaleString("fr")}</div><div class="iks">${t("k_success")}</div></div>
      <div class="ik ko"><div class="ikv mono">${(a.fail||0).toLocaleString("fr")}</div><div class="iks">${t("k_fail")}</div></div>
      <div class="ik"><div class="ikv mono">${cs.length}</div><div class="iks">${t("k_countries")}</div></div>
      <div class="ik"><div class="ikv mono">${(a.ips||[]).length}</div><div class="iks">${t("k_ips")}</div></div></div>`;
    h+=`<div class="lbl2">${t("inv_authmap")}</div>`+
      cs.slice(0,10).map(c=>`<div class="georow"><span class="gflag">${flagOf(c.k)}</span><span class="gcc">${esc(c.k)}</span>
        <div class="gbar"><div style="width:${Math.max(4,Math.round(c.n/cmax*100))}%"></div></div>
        <span class="gn mono">${(c.n||0).toLocaleString("fr")}</span></div>`).join("");
    h+=`<div class="lbl2">${t("inv_timeline")}</div><div class="invtl"><canvas id="invTl"></canvas></div>`;
    h+=`<div class="lbl2">${t("inv_ips")} <span class="muted" style="font-weight:400">${t("inv_ips_hint")}</span></div>`+
      (a.ips||[]).map(i=>`<div class="iprow"><span class="gflag">${flagOf(i.cc)}</span>
        <span class="ipa mono">${esc(i.ip)}</span><span class="ipc">${esc(i.cc||"")}</span>
        <span class="ipn mono">${i.n}</span><span class="ipb ${i.ok>0?'bok':'bko'}">${i.ok>0?i.ok+" "+t("succ_suffix"):t("none_suffix")}</span></div>`).join("");
    h+=`<div class="lbl2">${t("inv_codes")}</div><div>`+
      (a.codes||[]).map(c=>`<span class="pchip">${codeLabel(c.k)} · ${c.n}</span>`).join(" ")+`</div>`;}
  if(wn.total){
    h+=`<div class="lbl2">${t("inv_winauth")}</div><div class="invk">
      <div class="ik"><div class="ikv mono">${(wn.total||0).toLocaleString("fr")}</div><div class="iks">${t("k_logons")}</div></div>
      <div class="ik ok"><div class="ikv mono">${(wn.success||0).toLocaleString("fr")}</div><div class="iks">${t("k_success")}</div></div>
      <div class="ik ko"><div class="ikv mono">${(wn.fail||0).toLocaleString("fr")}</div><div class="iks">${t("k_fail")}</div></div></div>`;
    h+=`<div class="lbl2">${t("inv_logontypes")}</div><div>`+
      (wn.logon_types||[]).map(x=>`<span class="pchip">${ltype(x.k)} · ${x.n}</span>`).join(" ")+`</div>`;
    if((wn.reasons||[]).length)h+=`<div class="lbl2">${t("inv_failreasons")}</div><div>`+
      (wn.reasons||[]).map(x=>`<span class="pchip">${niceReason(x.k)} · ${x.n}</span>`).join(" ")+`</div>`;
    h+=`<div class="lbl2">${t("inv_timeline")}</div><div class="invtl"><canvas id="invTlW"></canvas></div>`;
    h+=`<div class="lbl2">${t("inv_ips")}</div>`+
      (wn.ips||[]).map(i=>`<div class="iprow"><span class="ipa mono">${esc(i.ip)}</span>
        <span class="ipn mono">${i.n}</span><span class="ipb ${i.ok>0?'bok':'bko'}">${i.ok>0?i.ok+" "+t("succ_suffix"):t("none_suffix")}</span></div>`).join("");}
  if(det.length){h+=`<div class="lbl2">${t("inv_prov")} <span class="muted" style="font-weight:400">— ${t("g_hint")}</span></div>`+
    det.map((x,gi)=>`<div class="erow gxrow" data-onclick="toggleG('gx${gi}')"><span class="gcar">▸</span><b>${nice(x.tag)}</b> <span class="srcb">${esc(x.source||"")}</span> <span class="mono">${x.n}</span> <span class="ts">${ago(x.last)}</span></div><div id="gx${gi}" class="gwrap" style="display:none">${guidanceBlock(x.tag)}</div>`).join("");}
  if(src.length){h+=`<div class="lbl2">${t("inv_presence")} (${d.days} ${daySuffix})</div><div>`+
    src.map(s=>`<span class="pchip">${esc(s.k)} · ${(s.n||0).toLocaleString("fr")}</span>`).join(" ")+`</div>`;}
  w.innerHTML=`<div class="blk inv"><div class="lbl">${ic("globe")} ${t("inv_title")}</div>${h||'<div class="muted">'+t("inv_none")+'</div>'}</div>`;
  if(a.total&&(a.timeline||[]).length){const tl=a.timeline;
    mk("invTl",{type:"bar",data:{labels:tl.map(x=>(x.t||"").slice(5)),datasets:[
      {label:t("ch_ok"),data:tl.map(x=>x.ok),backgroundColor:"#34d399",stack:"s"},
      {label:t("ch_ko"),data:tl.map(x=>x.ko),backgroundColor:"#f87171",stack:"s"}]},
      options:{maintainAspectRatio:false,plugins:{legend:{labels:{boxWidth:10,font:{size:10}}}},
        scales:{x:{stacked:true,grid:{display:false}},y:{stacked:true,beginAtZero:true}}}});}
  if(wn.total&&(wn.timeline||[]).length){const tl=wn.timeline;
    mk("invTlW",{type:"bar",data:{labels:tl.map(x=>(x.t||"").slice(5)),datasets:[
      {label:t("ch_ok"),data:tl.map(x=>x.ok),backgroundColor:"#34d399",stack:"s"},
      {label:t("ch_ko"),data:tl.map(x=>x.ko),backgroundColor:"#f87171",stack:"s"}]},
      options:{maintainAspectRatio:false,plugins:{legend:{labels:{boxWidth:10,font:{size:10}}}},
        scales:{x:{stacked:true,grid:{display:false}},y:{stacked:true,beginAtZero:true}}}});}}
function closeEnt(){$("#emodal").classList.remove("on");}

// --- Flux temps réel (SSE) ---
let liveN=0,liveES=null;
function startLive(){try{if(liveES)liveES.close();liveES=new EventSource(API+"/stream");
  liveES.onmessage=e=>{try{addLive(JSON.parse(e.data));}catch(_){}};}catch(_){}}
function addLive(ev){const el=$("#liveFeed");if(!el)return;if(liveN===0)el.innerHTML="";liveN++;
  const c=ev.sev?sevClass(ev.sev):(ev.priority==3?"critical":ev.priority==2?"high":"medium");
  const who=((ev.user||ev.entity||"")+"").split("\\").pop();
  const r=document.createElement("div");r.className="lrow sev-"+c;
  if(who)r.onclick=()=>openEntity(ev.user||ev.entity,who);
  r.innerHTML=`<span class="ld"></span><b>${nice(ev.tag)}</b> <em>${esc(ev.tech||"")}</em> <span class="who">${esc(who)}</span><span class="lt">${new Date().toLocaleTimeString("fr")}</span>`;
  el.prepend(r);while(el.children.length>25)el.removeChild(el.lastChild);
  const b=$("#liveCount");if(b)b.textContent=liveN+" évén.";}

// --- Command palette (Cmd/Ctrl+K) ---
const CMDPAGES=["overview","soar","ops","incidents","detections","entities","attack","graph","twin","ems","network","deploy","globe","leaks","health","report","playbooks"];
function CMDLIST(){return CMDPAGES.map(p=>({k:(titles[LANG]||titles.fr)[p],p:p}));}
function goNav(p){const a=document.querySelector('#nav a[data-p="'+p+'"]');if(a)a.click();}
function openPal(){$("#pal").classList.add("on");const i=$("#palIn");i.value="";renderPal("");setTimeout(()=>i.focus(),30);}
function closePal(){$("#pal").classList.remove("on");}
let PALTOK=0,PALENT=[];
function renderPal(q){q=(q||"").trim();const ql=q.toLowerCase();
  const cmds=CMDLIST().filter(c=>c.k.toLowerCase().includes(ql));
  const cmdHtml=cmds.map((c,i)=>`<div class="pi${i===0?" sel":""}" data-onclick="goNav('${c.p}');closePal();">▸ ${c.k}</div>`).join("");
  const logItem=q.length>=2?'<div class="pi" data-onclick="palSearchLogs('+JSON.stringify(q).replace(/"/g,'&quot;')+')">'+ic("search")+' '+(LANG==="en"?"Search":"Rechercher")+' « '+esc(q)+' » '+(LANG==="en"?"in logs":"dans les logs")+'</div>':'';
  $("#palList").innerHTML=cmdHtml+logItem||'<div class="muted" style="padding:12px">'+(LANG==="en"?"Type ≥ 2 chars…":"Tapez ≥ 2 caractères…")+'</div>';
  if(q.length>=2){const tok=++PALTOK;
    j("/entity-search?q="+encodeURIComponent(q)).then(r=>{if(tok!==PALTOK)return;PALENT=r.results||[];
      const ents=PALENT.map((e,i)=>`<div class="pi" data-onclick="openPalEnt(${i})">${e.kind==="host"?ic("cpu"):(e.kind==="ip"?ic("globe"):"👤")} ${esc(e.entity)} <span class="muted" style="font-size:11px">· ${(e.n||0).toLocaleString('fr')} ${t("pal_evts")}</span></div>`).join("");
      $("#palList").innerHTML=cmdHtml+logItem+(ents?'<div class="muted" style="padding:8px 12px 4px;font-size:10px;letter-spacing:1px">ENTITÉS</div>'+ents:'');
    }).catch(()=>{});}}
function palSearchLogs(q){const tok=++PALTOK;
  $("#palList").innerHTML='<div class="muted" style="padding:12px">'+(LANG==="en"?"Searching logs…":"Recherche dans les logs…")+'</div>';
  j("/search?q="+encodeURIComponent(q)+"&size=30").then(r=>{if(tok!==PALTOK)return;
    if(r&&r.error){$("#palList").innerHTML='<div class="muted" style="padding:12px">'+(LANG==="en"?"Invalid query.":"Requête invalide.")+'</div>';return;}
    const rs=(r&&r.results)||[];
    const head='<div class="muted" style="padding:8px 12px 4px;font-size:10px;letter-spacing:1px">LOGS · '+((r&&r.total)||0).toLocaleString('fr')+(LANG==="en"?" hits (2d)":" résultats (2j)")+'</div>';
    const rows=rs.map(e=>{const ent=e.ip||e.host||e.user;
      return '<div class="pi" style="display:block"'+(ent?' data-onclick="closePal();openEntity(\''+_jsq(ent)+'\',\''+_jsq(ent)+'\')"':'')+'>'
        +'<div style="display:flex;gap:7px;align-items:center;font-size:11px;flex-wrap:wrap"><span class="mono" style="color:var(--dim)">'+(e.ts?esc(e.ts.slice(5,19)):'')+'</span>'
        +(e.src?'<span class="chip">'+esc(e.src)+'</span>':'')+(e.tag?'<b style="color:var(--cy)">'+nice(e.tag)+'</b>':'')
        +(e.ip?'<span class="mono">'+esc(e.ip)+'</span>':'')+(e.seg?'<span style="color:var(--cy)">'+esc(e.seg)+'</span>':'')+(e.host?'<span>'+esc(e.host)+'</span>':'')+'</div>'
        +'<div class="muted mono" style="font-size:11px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc((e.msg||'').slice(0,150))+'</div></div>';}).join('');
    $("#palList").innerHTML=head+(rows||'<div class="muted" style="padding:12px">'+(LANG==="en"?"No result.":"Aucun résultat.")+'</div>');
  }).catch(()=>{$("#palList").innerHTML='<div class="muted" style="padding:12px">'+(LANG==="en"?"Search error.":"Erreur de recherche.")+'</div>';});}
function openPalEnt(i){const e=PALENT[i];if(!e)return;closePal();openEntity(e.entity,((e.entity||"")+"").split("\\").pop());}
document.addEventListener("keydown",e=>{
  if((e.metaKey||e.ctrlKey)&&(e.key==="k"||e.key==="K")){e.preventDefault();openPal();return;}
  if(e.key==="Escape"){closePal();closeEnt();closeHelp();closeSim();}
  // Raccourcis chiffres : 1..9 = onglet N (hors saisie, sans modificateur, palette fermée).
  if(!e.metaKey&&!e.ctrlKey&&!e.altKey&&/^[1-9]$/.test(e.key)
     &&!/^(INPUT|TEXTAREA|SELECT)$/.test(((e.target||{}).tagName)||"")
     &&!$("#pal").classList.contains("on")){
    const navs=document.querySelectorAll("#nav a");const idx=+e.key-1;
    if(navs[idx]){e.preventDefault();navs[idx].click();}return;}
  if(e.key==="Enter"&&$("#pal").classList.contains("on")){const f=$("#palList .pi");if(f)f.click();}
  if((e.key==="?"||((e.key==="/"||e.key==="Divide")&&e.shiftKey))&&!e.metaKey&&!e.ctrlKey&&!e.altKey){
    var t=e.target,tn=t&&t.tagName;
    if(tn==="INPUT"||tn==="TEXTAREA"||tn==="SELECT"||(t&&t.isContentEditable))return;
    if($("#pal")&&$("#pal").classList.contains("on"))return;
    if($("#emodal")&&$("#emodal").classList.contains("on"))return;
    e.preventDefault();_hToggleHelp();return;
  }});
function layoutGraph(){if(cy){cy.resize();cy.layout(GCFG).run();cy.fit(undefined,30);}}
// === Feedback non bloquant — toasts (verre + accent) =======================
var TOAST_META={
  ok:  {ic:"✓", ac:"grn", title:"Succès"},
  info:{ic:"◈", ac:"cy",  title:"Information"},
  warn:{ic:"▲", ac:"amb", title:"Attention"},
  err: {ic:"✕", ac:"red", title:"Erreur"}
};
function toastHost(){
  var h=document.getElementById("toasts");
  if(!h){h=document.createElement("div");h.id="toasts";h.setAttribute("aria-live","polite");document.body.appendChild(h);}
  return h;
}
function toastClose(el){
  if(!el||el.dataset.closing)return;
  el.dataset.closing="1";
  el.classList.add("out");
  setTimeout(function(){if(el&&el.parentNode)el.parentNode.removeChild(el);},260);
}
function toast(msg,type,opts){
  opts=opts||{};
  var m=TOAST_META[type]||TOAST_META.info;
  var host=toastHost();
  while(host.children.length>=5)toastClose(host.firstChild);
  var ttl=opts.sticky?0:(opts.ttl||4200);
  var el=document.createElement("div");
  el.className="toast t-"+m.ac;
  el.innerHTML='<div class="ti">'+m.ic+'</div>'
    +'<div class="tb"><div class="tt">'+esc(opts.title||m.title)+'</div>'
    +'<div class="tm">'+esc(msg||"")+'</div></div>'
    +'<button class="tx" aria-label="Fermer">×</button>'
    +(ttl?'<div class="tp"><i style="animation-duration:'+ttl+'ms"></i></div>':'');
  el.querySelector(".tx").onclick=function(){toastClose(el);};
  host.appendChild(el);
  if(ttl){
    var timer=setTimeout(function(){toastClose(el);},ttl);
    el.onmouseenter=function(){clearTimeout(timer);var bar=el.querySelector(".tp i");if(bar)bar.style.animationPlayState="paused";};
    el.onmouseleave=function(){var bar=el.querySelector(".tp i");if(bar)bar.style.animationPlayState="running";timer=setTimeout(function(){toastClose(el);},1400);};
  }
  return el;
}
function toastOk(m,o){return toast(m,"ok",o);}
function toastInfo(m,o){return toast(m,"info",o);}
function toastWarn(m,o){return toast(m,"warn",o);}
function toastErr(m,o){return toast(m,"err",o);}
var _netToastAt=0;
function toastNet(msg){
  var now=Date.now();
  if(now-_netToastAt<4000)return;
  _netToastAt=now;
  toastErr(msg||"Connexion au SIEM interrompue — nouvelle tentative automatique.",{title:"Réseau"});
}
var KTREND={};
function renderKpiTrend(t){KTREND=t||{};
  var keys=["incidents_critiques_7j","hotes_risque_ueba","alertes_24h","kev_exposees"];
  var cards=document.querySelectorAll("#kpis .kpi");
  for(var i=0;i<cards.length;i++){
    var d=KTREND[keys[i]];
    if(!d){continue;}
    var old=cards[i].querySelector(".kpitrend");
    if(old){old.parentNode.removeChild(old);}
    if(d.dir==="flat"){continue;}
    var up=d.dir==="up";
    var arrow=up?"▲":"▼";
    var cls=d.bad?"kt-bad":"kt-good";
    var b=document.createElement("span");
    b.className="kpitrend "+cls;
    b.title="vs période précédente ("+((d.prev||0)).toLocaleString("fr")+")";
    b.textContent=arrow+" "+(d.pct||0)+"%";
    var val=cards[i].querySelector(".val");
    if(val){val.appendChild(b);}else{cards[i].appendChild(b);}
  }
}
// ===== Graphe d'attaque filtrable (filtrage 100% client) =====
function gFilterState(){
  var sel=$("#gTactic"),sl=$("#gMinVol"),se=$("#gSearch");
  return {tactic: sel?sel.value:"", minVol: sl?(parseInt(sl.value,10)||0):0, q: se?(se.value||"").trim().toLowerCase():""};
}
function gPopulate(){
  if(!GRAPH)return;
  var nodes=GRAPH.nodes||[],edges=GRAPH.edges||[];
  var present={};
  nodes.forEach(function(n){if(n.type==="technique"&&n.tactic&&n.tactic!=="?")present[n.tactic]=1;});
  var order=Object.keys(TACCOL),ordered=[];
  order.forEach(function(t){if(present[t]){ordered.push(t);delete present[t];}});
  Object.keys(present).forEach(function(t){ordered.push(t);});
  var sel=$("#gTactic");
  if(sel){var cur=sel.value;
    sel.innerHTML='<option value="">Toutes tactiques</option>'+ordered.map(function(t){return '<option value="'+esc(t)+'">'+esc(t)+'</option>';}).join("");
    sel.value=cur;}
  var dl=$("#gEntList");
  if(dl){dl.innerHTML=nodes.filter(function(n){return n.type==="entity";}).map(function(n){return '<option value="'+esc(n.label)+'">';}).join("");}
  var mx=0;edges.forEach(function(e){if((e.weight||0)>mx)mx=e.weight||0;});
  var slv=$("#gMinVol");
  if(slv){slv.max=mx>1?mx:1;if((parseInt(slv.value,10)||0)>slv.max)slv.value=0;gMinLbl();}
}
function gMinLbl(){var sl=$("#gMinVol"),lb=$("#gMinVal");if(sl&&lb)lb.textContent="≥ "+(parseInt(sl.value,10)||0);}
function applyGraphFilter(){
  if(!GRAPH){return;}
  var f=gFilterState();
  var nodes=GRAPH.nodes||[],edges=GRAPH.edges||[];
  var byId={};nodes.forEach(function(n){byId[n.id]=n;});
  var keepEdges=edges.filter(function(e){
    if((e.weight||0)<f.minVol)return false;
    if(f.tactic){var tn=byId[e.target];if(!tn||tn.tactic!==f.tactic)return false;}
    return true;});
  var keepN={};keepEdges.forEach(function(e){keepN[e.source]=1;keepN[e.target]=1;});
  var keepNodes=nodes.filter(function(n){return keepN[n.id];});
  buildGraphView({nodes:keepNodes,edges:keepEdges});
  layoutGraph();
  gFocusEntity(f.q);
  var cnt=$("#gCount");if(cnt)cnt.textContent=keepNodes.length+" nœuds · "+keepEdges.length+" liens";
}
function gFocusEntity(q){
  if(!cy)return;
  cy.elements().removeClass("ghit gdim");
  if(!q)return;
  var hits=cy.nodes('[type="entity"]').filter(function(el){return (""+el.data("label")).toLowerCase().indexOf(q)>=0;});
  if(hits.length===0)return;
  cy.elements().addClass("gdim");
  hits.closedNeighborhood().removeClass("gdim");
  hits.addClass("ghit");
  cy.animate({fit:{eles:hits,padding:120}},{duration:350});
}
function gClear(){if($("#gTactic"))$("#gTactic").value="";if($("#gMinVol"))$("#gMinVol").value=0;if($("#gSearch"))$("#gSearch").value="";gMinLbl();applyGraphFilter();}
// ===== Entite-360 : scores + pagination =====
var ENT_CUR=null,ENT_SIZE=20;
function entMore(){ENT_SIZE+=20;if(ENT_CUR)openEntity(ENT_CUR.full,ENT_CUR.label,ENT_SIZE);}
function entScoreBanner(d){
  var r=d.risk||null, out="";
  var ml=d.scores&&d.scores.ml?d.scores.ml:null;
  var ue=d.scores&&d.scores.ueba?d.scores.ueba:null;
  // Jauge de RISQUE FUSIONNÉ (ML + UEBA + détections) = la priorisation
  if(r&&r.score!==null&&r.score!==undefined){
    var rc=r.score>=80?"red":r.score>=60?"amb":r.score>=35?"vio":"cy";
    var c=r.components||{};
    var bar=function(v,lab){v=v||0;var bc=v>=70?"#fb3b53":v>=45?"#f5a623":"#3b82f6";
      return '<div class="rbk"><span class="rbl">'+lab+'</span><span class="rbt"><span class="rbf" style="width:'+Math.max(3,Math.min(100,v))+'%;background:'+bc+'"></span></span><span class="rbv mono">'+v+'</span></div>';};
    out+='<div class="riskbanner '+rc+'"><div class="rg"><div class="rgs mono">'+r.score+'</div>'+
      '<div class="rgmeta"><div class="rgl">'+t("risk_"+(r.label||"minimal"))+'</div><div class="rgsub">'+t("risk_fused")+'</div></div></div>'+
      '<div class="rcomp">'+bar(c.ml,t("esc_ml"))+bar(c.ueba,t("esc_ueba"))+bar(c.detection,t("risk_det"))+
      (r.corroboration>=2?'<div class="rcorr">'+ic("network")+' '+t("risk_corrob")+'</div>':'')+'</div></div>';
  }
  // Détail ML/UEBA (motif/facteur) en complément
  var cards="";
  if(ml&&ml.score!==null&&ml.score!==undefined&&ml.reason)
    cards+='<div class="escore cy"><div class="escK">'+t("esc_ml")+'</div><div class="escV">'+esc(""+ml.score)+'</div><div class="escR">'+esc((ml.reason+"").slice(0,80))+'</div></div>';
  if(ue&&ue.score!==null&&ue.score!==undefined&&ue.factor)
    cards+='<div class="escore vio"><div class="escK">'+t("esc_ueba")+'</div><div class="escV">'+esc(""+ue.score)+'</div><div class="escR">'+esc((ue.factor+"").slice(0,80))+'</div></div>';
  if(cards)out+='<div class="escRow">'+cards+'</div>';
  return out;
}
/* ===== Polish chargement / rafraichissement (additif) ===== */
var UPD_AT=0, UPD_T=null, REFRESH_T=null, RELOADING=false;
function fmtAgoShort(ms){
  if(!ms)return "jamais";
  var s=Math.max(0,Math.floor((Date.now()-ms)/1000));
  if(s<60)return "il y a "+s+" s";
  if(s<3600)return "il y a "+Math.floor(s/60)+" min";
  return "il y a "+Math.floor(s/3600)+" h";
}
function markUpdated(){UPD_AT=Date.now();tickUpd();}
function tickUpd(){
  var el=$("#updPill");if(!el)return;
  var lbl=el.querySelector(".updtxt");if(!lbl)return;
  if(RELOADING){lbl.textContent="actualisation…";return;}
  lbl.textContent="Mis à jour "+fmtAgoShort(UPD_AT);
}
function setSpin(on){
  var b=$("#refBtn");if(!b)return;
  if(on)b.classList.add("spin");else b.classList.remove("spin");
  b.setAttribute("aria-busy",on?"true":"false");
}
function refreshNow(){if(RELOADING)return;loadAll();}
function getCadence(){
  var v=null;try{v=localStorage.getItem("soc.cadence");}catch(_){v=null;}
  if(v!=="30000"&&v!=="60000"&&v!=="0")v="60000";
  return v;
}
function applyCadence(){
  if(REFRESH_T){clearInterval(REFRESH_T);REFRESH_T=null;}
  var v=getCadence();
  var sel=$("#cadSel");if(sel)sel.value=v;
  if(v==="0")return;
  REFRESH_T=setInterval(function(){if(!document.hidden&&!RELOADING)loadAll();},parseInt(v,10));
}
function setCadence(v){
  try{localStorage.setItem("soc.cadence",v);}catch(_){}
  applyCadence();
}
function startRefresh(){
  if(!UPD_T){UPD_T=setInterval(tickUpd,1000);}
  applyCadence();
}
// === AXE D — Aide & ergonomie (panneau d'aide + bascule de densité) ========
var SOC_BUILD = "v1 · build 2026-06-22";
function _hToggleHelp(){var m=$("#help");if(m&&m.classList.contains("on"))closeHelp();else openHelp();}
var HELP_OPENER=null;
function openHelp(){
  var m=$("#help");if(!m)return;
  buildHelp();
  var act=document.activeElement;
  if(act&&!m.contains(act))HELP_OPENER=act;
  m.classList.add("on");m.setAttribute("aria-hidden","false");
  var b=$("#helpBtn");if(b)b.setAttribute("aria-expanded","true");
  setTimeout(function(){var x=m.querySelector(".helpClose");if(x){try{x.focus();}catch(_){}}},40);
}
function closeHelp(){
  var m=$("#help");if(!m||!m.classList.contains("on"))return;
  m.classList.remove("on");m.setAttribute("aria-hidden","true");
  var b=$("#helpBtn");if(b)b.setAttribute("aria-expanded","false");
  if(HELP_OPENER){var o=HELP_OPENER;HELP_OPENER=null;setTimeout(function(){try{if(o&&o.focus)o.focus();}catch(_){}},0);}
}
document.addEventListener("keydown",function(e){
  if(e.key!=="Tab")return;
  var m=$("#help");if(!m||!m.classList.contains("on"))return;
  var scope=m.querySelector(".helpbox")||m;
  var nodes=scope.querySelectorAll('a[href],button,input,select,textarea,[tabindex]');
  var f=[];for(var i=0;i<nodes.length;i++){var el=nodes[i];if(el.disabled)continue;if(el.getAttribute("tabindex")==="-1")continue;if(el.offsetParent===null&&el.tagName!=="INPUT")continue;f.push(el);}
  if(!f.length){e.preventDefault();return;}
  var first=f[0],last=f[f.length-1],a=document.activeElement;
  if(!m.contains(a)){e.preventDefault();try{first.focus();}catch(_){}return;}
  if(e.shiftKey&&a===first){e.preventDefault();try{last.focus();}catch(_){}}
  else if(!e.shiftKey&&a===last){e.preventDefault();try{first.focus();}catch(_){}}
},true);
function _densRead(){var v=null;try{v=localStorage.getItem("soc.density");}catch(_){v=null;}return v==="compact"?"compact":"comfortable";}
function applyDensity(mode){
  var compact=mode==="compact";
  document.body.classList.toggle("compact",compact);
  try{localStorage.setItem("soc.density",compact?"compact":"comfortable");}catch(_){}
  var btn=$("#densBtn");
  if(btn){
    btn.setAttribute("aria-pressed",compact?"true":"false");
    btn.title=compact?"Densité compacte — cliquer pour confortable":"Densité confortable — cliquer pour compact";
    var lab=btn.querySelector(".densLab");if(lab)lab.textContent=compact?t("dens_compact"):t("dens_comfort");
  }
  var hb=$("#helpDensState");if(hb)hb.textContent=compact?"compacte":"confortable";
}
function toggleDensity(){applyDensity(_densRead()==="compact"?"comfortable":"compact");}
applyDensity(_densRead());
function buildHelp(){
  var box=$("#helpBody");if(!box||box.dataset.built)return;box.dataset.built="1";
  var EN=LANG==="en";
  var KEYS=EN?[
    ["Ctrl / Cmd + K","Open the palette — search a page or entity"],
    ["?","Open / close this help panel"],
    ["Esc","Close the palette, a profile or help"],
    ["Enter / Space","Activate the target element (rows, cells, KPIs)"],
    ["Tab","Keyboard navigation — focus trapped in modals"]
  ]:[
    ["Ctrl / Cmd + K","Ouvrir la palette — chercher une page ou une entité"],
    ["?","Ouvrir / fermer ce panneau d'aide"],
    ["Échap","Fermer la palette, une fiche ou l'aide"],
    ["Entrée / Espace","Activer l'élément cible (lignes, cellules, KPI)"],
    ["Tab","Naviguer au clavier — focus confiné dans les modales"]
  ];
  var PAGES=EN?[
    [ic("grid"),"Overview","Posture at a glance: KPIs, 24h activity, ATT&CK tactics and live feed. Everything is clickable."],
    [ic("alert"),"Incidents","Correlated case queue (oms-xdr): status, assignment, investigation notes."],
    [ic("target"),"Detections","Tagged detections from the last 24h, filterable by tactic and source; CSV export."],
    [ic("matrix"),"MITRE ATT&CK","Coverage matrix: each detected cell, colored by real activity volume."],
    [ic("network"),"Attack graph","Links users and triggered techniques: size = volume, color = tactic."],
    [ic("unlock"),"Leaks & Dark Web","Extortion sites (RansomLook), exposed accounts (HIBP/Dehashed), public code (GitHub)."],
    [ic("pulse"),"Health & Collection","Volume and freshness of each source; going dark = alerted blind spot (ISO A.8.15)."],
    [ic("doc"),"Report","Printable executive summary (PDF) for management and ISO audit."]
  ]:[
    [ic("grid"),"Vue d'ensemble","Posture en un coup d'œil : KPI, activité 24 h, tactiques ATT&CK et flux temps réel. Tout est cliquable."],
    [ic("alert"),"Incidents","File des cas corrélés (oms-xdr) : statut, assignation, notes d'investigation."],
    [ic("target"),"Détections","Détections taguées des dernières 24 h, filtrables par tactique et par source ; export CSV."],
    [ic("matrix"),"MITRE ATT&CK","Matrice de couverture : chaque cellule détectée, colorée selon le volume réel d'activité."],
    [ic("network"),"Graphe d'attaque","Relie utilisateurs et techniques déclenchées : taille = volume, couleur = tactique."],
    [ic("unlock"),"Fuites & Dark Web","Sites d'extorsion (RansomLook), comptes exposés (HIBP/Dehashed), code public (GitHub)."],
    [ic("pulse"),"Santé & Collecte","Volume et fraîcheur de chaque source ; décrochage = angle mort alerte (ISO A.8.15)."],
    [ic("doc"),"Rapport","Synthèse exécutive imprimable (PDF) pour la direction et l'audit ISO."]
  ];
  var GLOSS=EN?[
    ["ML score","Anomaly assigned by the unsupervised oms-ml model (IsolationForest). The higher the score, the further the behavior deviates from the learned norm."],
    ["UEBA","User &amp; Entity Behavior Analytics — behavioral risk score aggregated per entity over 24h (volume, technique diversity, severity)."],
    ["Severity","Detection severity: critical (red), high (amber), medium, low. Drives alert routing and handling priority."],
    ["Go-dark","Silent host: no data received for &gt; 26h. Signals a loss of visibility (agent failure, isolation, bypass) to check."],
    ["KEV","Known Exploited Vulnerabilities (CISA) — actively exploited flaws; their exposure is tracked as a priority."],
    ["Kill-chain","Sequence of attack stages (initial access → execution → … → impact) reconstructed by incident correlation."]
  ]:[
    ["Score ML","Anomalie attribuée par le modèle non supervisé oms-ml (IsolationForest). Plus le score est élevé, plus le comportement s'écarte de la normale apprise."],
    ["UEBA","User &amp; Entity Behavior Analytics — score de risque comportemental agrégé par entité sur 24 h (volume, diversité de techniques, sévérité)."],
    ["Sévérité","Gravité d'une détection : critique (rouge), élevée (ambre), moyenne, faible. Pilote le routage des alertes et la priorité de traitement."],
    ["Go-dark","Hôte muet : aucune donnée reçue depuis &gt; 26 h. Signale une perte de visibilité (panne d'agent, isolement, contournement) à vérifier."],
    ["KEV","Known Exploited Vulnerabilities (CISA) — failles activement exploitées ; leur exposition est suivie en priorité."],
    ["Kill-chain","Enchaînement des étapes d'une attaque (accès initial → exécution → … → impact) reconstitué par la corrélation d'incidents."]
  ];
  var h="";
  h+='<div class="hsec"><div class="hsk">'+(EN?"Keyboard shortcuts":"Raccourcis clavier")+'</div><div class="hkeys">';
  for(var i=0;i<KEYS.length;i++)h+='<div class="hkey"><kbd>'+esc(KEYS[i][0])+'</kbd><span>'+esc(KEYS[i][1])+'</span></div>';
  h+='</div></div>';
  h+='<div class="hsec"><div class="hsk">'+(EN?"Pages":"Les pages")+'</div><div class="hpages">';
  for(var p=0;p<PAGES.length;p++)h+='<div class="hpg"><span class="hic">'+PAGES[p][0]+'</span><div><b>'+esc(PAGES[p][1])+'</b><em>'+esc(PAGES[p][2])+'</em></div></div>';
  h+='</div></div>';
  h+='<div class="hsec"><div class="hsk">'+(EN?"Signal glossary":"Glossaire des signaux")+'</div><div class="hgloss">';
  for(var g=0;g<GLOSS.length;g++)h+='<div class="hgl"><b>'+esc(GLOSS[g][0])+'</b><span>'+GLOSS[g][1]+'</span></div>';
  h+='</div></div>';
  box.innerHTML=h;
  var bf=$("#helpBuild");if(bf)bf.textContent=SOC_BUILD;
  var hb=$("#helpDensState");if(hb)hb.textContent=EN?(_densRead()==="compact"?"compact":"comfortable"):(_densRead()==="compact"?"compacte":"confortable");
}
function renderReport(d){d=d||{};const k=d.kpis||{};const dt=new Date().toLocaleString("fr");
  const top=(d.top_detections||[]).map(t=>`<tr><td>${nice(t.k)}</td><td class="num">${(t.n||0).toLocaleString("fr")}</td></tr>`).join("");
  const inc=(d.incidents||[]).map(i=>`<tr><td>${esc((i.severity||'?').toUpperCase())}</td><td>${esc(i.title)}</td><td>${esc((i.entities||'').toString())}</td><td>${esc((i.mitre||'').toString())}</td></tr>`).join("")||`<tr><td colspan="4" class="muted">${t("rep_noinc")}</td></tr>`;
  const src=(d.sources||[]).slice(0,12).map(s=>`<tr><td>${esc(s.k)}</td><td class="num">${(s.n||0).toLocaleString("fr")}</td></tr>`).join("");
  const cov=d.coverage||{};const sla=d.sla||{},rob=d.robots||{};
  const mlr=(d.ml_top||[]).map(m=>`<tr><td>${esc(m.entity)}</td><td class="num">${m.score}</td><td>${esc((m.reason||"").slice(0,80))}</td></tr>`).join("")||'<tr><td colspan="3" class="muted">—</td></tr>';
  const ubr=(d.ueba_top||[]).map(u=>`<tr><td>${esc(u.entity)}</td><td class="num">${u.score}</td><td>${esc(u.factor||"")}</td></tr>`).join("")||'<tr><td colspan="3" class="muted">—</td></tr>';
  const dark=(d.dark_hosts||[]).map(h=>esc(h.host)+" ("+h.hours+"h)").join(", ");
  const REN=LANG==="en";const N=d.network||{},EM=d.endpoint_ems||{},integ=d.integrations||[];
  const integTxt=integ.map(i=>esc(i.k)+" : "+i.status).join(" · ");
  const onprem=`<h2>${REN?"On-prem sources & endpoint":"Sources on-prem & endpoint"}</h2>
   <p>${REN?"Aruba switches":"Switches Aruba"} : <b>${N.switches||0}</b> (${(N.aruba||0).toLocaleString("fr")} ev) · Linux : <b>${(N.linux||0).toLocaleString("fr")}</b> · DNS : <b>${(N.dns||0).toLocaleString("fr")}</b> · Endpoint EMS : <b>${EM.malware||0}</b> malware / <b>${EM.vuln||0}</b> vuln / <b>${EM.av_off||0}</b> ${REN?"protection off":"protection off"}.</p>
   ${integ.length?`<p class="muted">${REN?"Expected integrations":"Intégrations attendues"} — ${integTxt}.</p>`:''}`;
  $("#reportBody").innerHTML=`
   <div class="rhead"><div><h1>${t("rep_title")}</h1><div class="muted">${t("rep_gen")} ${dt} · ${t("rep_plat")}</div></div><div class="rlogo">⬢</div></div>
   <div class="rkpi"><div><b>${k.incidents_critiques_7j??0}</b><span>${t("rep_k_inc")}</span></div>
     <div><b>${(k.alertes_24h??0).toLocaleString("fr")}</b><span>${t("rep_k_det")}</span></div>
     <div><b>${cov.techniques??'?'}</b><span>${t("rep_k_tech")}</span></div>
     <div><b>${(d.events_24h??0).toLocaleString("fr")}</b><span>${t("rep_k_evt")}</span></div></div>
   <h2>${t("rep_cov")}</h2><p>${cov.techniques??'?'} ${t("rep_cov1")} ${cov.tactics??'?'} ${t("rep_cov2")} <b>${esc(d.cluster||'?')}</b>.</p>
   <h2>${t("rep_posture")}</h2><p>${t("rep_robots")} <b>${rob.health_ok??'?'}/${rob.health_total??'?'}</b> ${t("rep_oper")}${rob.health_fail?` — <b style="color:#b91c1c">${rob.health_fail} ${t("rep_down")}</b>`:''}. ${t("rep_collect")} <b>${sla.sla_coverage_pct??'?'} %</b> (${sla.sla_go_dark??0} ${t("rep_sil1")} ${sla.sla_expected??0} ${t("rep_sil2")}).${dark?`<br><span class="muted">${t("rep_silh")} ${dark}.</span>`:''}</p>
   <h2>${t("rep_risk")}</h2>
   <div style="display:flex;gap:22px;flex-wrap:wrap">
     <div style="flex:1;min-width:300px"><h3 style="font-size:13px;margin:0 0 6px">${t("rep_mlanom")}</h3><table><thead><tr><th>${t("rep_h_ent")}</th><th class="num">${t("rep_h_score")}</th><th>${t("rep_h_reason")}</th></tr></thead><tbody>${mlr}</tbody></table></div>
     <div style="flex:1;min-width:300px"><h3 style="font-size:13px;margin:0 0 6px">${t("rep_uebar")}</h3><table><thead><tr><th>${t("rep_h_ent")}</th><th class="num">${t("rep_h_score")}</th><th>${t("rep_h_factor")}</th></tr></thead><tbody>${ubr}</tbody></table></div>
   </div>
   <h2>${t("rep_topdet")}</h2><table><thead><tr><th>${t("rep_h_det")}</th><th class="num">${t("rep_h_vol")}</th></tr></thead><tbody>${top}</tbody></table>
   <h2>${t("rep_recinc")}</h2><table><thead><tr><th>${t("rep_h_sev")}</th><th>${t("rep_h_title")}</th><th>${t("rep_h_ent")}</th><th>ATT&CK</th></tr></thead><tbody>${inc}</tbody></table>
   ${onprem}
   <h2>${t("rep_collsrc")}</h2><table><thead><tr><th>${t("rep_h_src")}</th><th class="num">${t("rep_h_vol")}</th></tr></thead><tbody>${src}</tbody></table>
   <div class="muted" style="margin-top:20px">${t("rep_foot")}</div>`;}
function renderHealth(d){d=d||{};const rb=d.robots||{},sl=d.sla||{},mt=d.maintenance||{};
  const mmsg=mt.message||mt.short_message||mt.health_reason;
  if($("#hmaint"))$("#hmaint").innerHTML=mmsg?`<div class="mbanner">${ic("warning")}<div><b>${t("maint_title")}</b><div class="msub">${esc(mmsg)}${mt.health_reason&&mt.health_reason!==mmsg?" — "+esc(mt.health_reason):""}</div></div></div>`:"";
  $("#hkpis").innerHTML=[
    ["cy","Cluster",esc(d.cluster||'?'),"OpenSearch"],
    ["cy","Événements (24 h)",(d.events_24h||0).toLocaleString("fr"),"toutes sources"],
    ["vio","Sources actives",(d.sources||[]).length,"sur 24 h"],
    ["amb","Shards actifs",(d.shards!=null?d.shards:'?'),((d.nodes!=null?d.nodes:'?'))+" nœud(s)"],
    ...(rb.health_total!=null?[[(rb.health_fail>0?"red":"cy"),"Robots actifs",(rb.health_ok||0)+"/"+rb.health_total,(rb.health_fail||0)+" en panne · auto‑supervision"]]:[]),
    ...(sl.sla_coverage_pct!=null?[["cy","Couverture collecte",sl.sla_coverage_pct+"%",(sl.sla_go_dark||0)+" go‑dark / "+(sl.sla_expected||0)+" attendus"]]:[])
  ].map(([c,l,v,s])=>`<div class="kpi ${c}"><div class="lab">${l}</div><div class="val mono">${v}</div><div class="sub">${s}</div></div>`).join("");
  const dk=d.dark_hosts||[];
  if($("#hdark"))$("#hdark").innerHTML=dk.length?dk.map(x=>`<div class="inc sev-high"><div class="top"><span class="ttl">🖥️ ${esc(x.host)}</span><span class="mono" style="color:var(--amb);margin-left:auto;font-weight:700">${x.hours} h</span></div></div>`).join(""):'<div class="empty">Aucun hôte silencieux ✅</div>';
  $("#hsrc").innerHTML=(d.sources||[]).map(x=>`<div class="inc"><div class="top">
    <span class="ttl">${esc(x.k)}</span>
    <span class="mono" style="color:var(--cy);margin-left:auto">${(x.n||0).toLocaleString("fr")}</span>
    <span class="ts">${ago(x.last)}</span></div></div>`).join("")||'<div class="empty">—</div>';
  const EN=LANG==="en";const SC={ok:"#2dd4a7",stale:"#f5a623",missing:"#fb3b53"};
  const SL={ok:"ok",stale:(EN?"slow":"lent"),missing:(EN?"absent":"absent")};
  if($("#hint"))$("#hint").innerHTML=(d.integrations||[]).map(i=>{const c=SC[i.status]||"#39507a";
    const age=i.age_min==null?(EN?"never":"jamais"):(i.age_min<60?i.age_min+" min":Math.round(i.age_min/60)+" h");
    return `<span class="pchip" style="border:1px solid ${c}66;color:${c}" title="${EN?'threshold':'seuil'} ${i.threshold_min} min">${esc(i.k)} · ${SL[i.status]||i.status} · ${age}</span>`;
  }).join("")||'<div class="empty">—</div>';}
let DETI=[],DETV=[],detF={tactic:"",source:"",technique:""},detQ="";
function onFilter(){detF.tactic=$("#fTactic").value;detF.source=$("#fSource").value;detF.technique="";loadDetections();}
function clearFilter(){detF={tactic:"",source:"",technique:""};detQ="";if($("#detSearch"))$("#detSearch").value="";if($("#fTactic"))$("#fTactic").value="";if($("#fSource"))$("#fSource").value="";loadDetections();}
function openTech(id){detF={tactic:"",source:"",technique:id};if($("#fTactic"))$("#fTactic").value="";if($("#fSource"))$("#fSource").value="";goNav("detections");loadDetections();}
function loadDetections(){j("/detections?tactic="+encodeURIComponent(detF.tactic)+"&source="+encodeURIComponent(detF.source)+"&technique="+encodeURIComponent(detF.technique||"")).then(d=>renderDetections(d)).catch(()=>{});}
function renderDetections(d){d=d||{};DETI=d.items||[];
  const ft=$("#fTactic");if(ft&&ft.options.length<=1)(d.tactics||[]).forEach(t=>ft.add(new Option(t,t)));
  const fs=$("#fSource");if(fs&&fs.options.length<=1)(d.sources||[]).forEach(s=>fs.add(new Option(s,s)));
  renderDetRows();}
function renderDetRows(){
  DETV=detQ?DETI.filter(x=>JSON.stringify([x.tag,x.entity,x.tech,x.tactic,x.source,x.msg]).toLowerCase().includes(detQ)):DETI.slice();
  if($("#detCount"))$("#detCount").textContent=(detF.technique?"▸ "+detF.technique+" · ":"")+DETV.length+" détection(s)"+(detQ?' · « '+detQ+' »':'');
  $("#detFeed").innerHTML=DETV.length?DETV.map((x,i)=>{const c=x.sev?sevClass(x.sev):(x.priority==3?"critical":x.priority==2?"high":"medium");
    const who=((x.entity||"")+"").split("\\").pop();
    const sevLbl=((LANG==="en")?{critical:'CRIT',high:'HIGH',medium:'MED',low:'LOW'}:{critical:'CRIT',high:'HAUT',medium:'MOY',low:'BAS'})[c]||((c||'').toUpperCase());
    return `<div class="inc sev-${c}" data-onclick="openDet(${i})" style="cursor:pointer"><div class="top">
      <span class="sevtag sevtag-${c}">${sevLbl}</span>
      <span class="chip ${chipCls(c)}">${esc((x.source||"").toUpperCase())}</span>
      <span class="ttl">${nice(x.tag)}</span>${x.score?`<span class="mono" style="color:var(--${c=='critical'?'red':c=='high'?'amb':'cy'});margin-left:auto;font-weight:700">${x.score}</span>`:""}<span class="ts">${ago(x.ts)}</span></div>
      <div class="meta">${esc(x.tech||"")}${x.tactic?" · "+esc(x.tactic):""}${who?" · 👤 "+esc(who):""}${GUIDANCE[x.tag]?`<a class="dgbtn" data-onclick="event.stopPropagation();toggleG('dg${i}')">${t("g_show")}</a>`:""}${x.entity?`<a class="dgbtn" data-onclick="event.stopPropagation();markFP(${i})" title="${(LANG==="en")?'Mark false positive — mute non-critical mail (critical stays)':'Marquer faux positif — sourdine du mail non-critique (le critique reste)'}">FP</a>`:""}</div>
      <div id="dg${i}" class="gwrap" style="display:none">${guidanceBlock(x.tag)}</div></div>`;}).join(""):'<div class="empty">'+t("empty_det")+'</div>';}
function markFP(i){var EN=LANG==="en";var x=DETV[i];if(!x||!x.entity){toastInfo(EN?"No entity to mute.":"Pas d'entité.");return;}
  var who=((x.entity||"")+"").split("\\").pop();var det=nice(x.tag||"")||(EN?"this detection":"cette détection");
  if(!confirm((EN?'Mark false positive: "':'Marquer faux positif : « ')+det+(EN?'" on ':' » sur ')+who+" ?\n"+(EN?"Only THIS detection's mail is muted (30 days). Critical / kill-chain alerts are never touched.":"Seul le mail de CETTE détection est mis en sourdine (30 jours). Les critiques / kill-chain ne sont jamais touchés.")))return;
  fetch(API+"/fp",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({entity:x.entity,tag:x.tag||"",title_sub:""})}).then(r=>r.json()).then(r=>{
    if(r&&r.ok!==false){toastOk((EN?"False positive recorded · ":"Faux positif enregistré · ")+det+" / "+who,{title:"FP"});}
    else{toastInfo("FP : "+((r&&r.error)||"?"));}
  }).catch(function(){toastInfo("FP");});}
function applyDetSearch(){detQ=(($("#detSearch")||{}).value||"").toLowerCase().trim();renderDetRows();}
function exportDetections(){const rows=DETV.length?DETV:DETI;if(!rows.length){toastInfo("Aucune détection à exporter pour ce filtre.");return;}const cols=["ts","sev","score","tag","tech","tactic","source","entity","msg"];
  const csv=[cols.join(",")].concat(rows.map(r=>cols.map(k=>'"'+((r[k]==null?"":r[k])+"").replace(/"/g,'""')+'"').join(","))).join("\n");
  const a=document.createElement("a");a.href=URL.createObjectURL(new Blob(["﻿"+csv],{type:"text/csv;charset=utf-8"}));a.download="detections_omni_soc.csv";a.click();
  toastOk("Export CSV généré — "+rows.length.toLocaleString("fr")+" détection"+(rows.length>1?"s":"")+".",{title:"Export"});}
function openDet(i){const x=DETV[i];if(!x||!x.entity)return;openEntity(x.entity,((x.entity||"")+"").split("\\").pop());}
// deep-link depuis un mail : #e=<entite> -> ouvre directement le dossier 360
function deepLink(){var h=location.hash||"";var m=h.match(/[#&]e=([^&]+)/);if(!m)return;try{var ent=decodeURIComponent(m[1]);if(ent)openEntity(ent,((ent||"")+"").split("\\").pop());}catch(e){}}
var LEAK_CATS=[
  {id:"extortion",ic:"🏴‍☠️",lab:"Extorsion ransomware",sub:"sites de fuite (RansomLook)",kpi:"red",sev:"critical",vc:"red"},
  {id:"creds",ic:"🔑",lab:"Identifiants exposés",sub:"comptes / breaches (HIBP · Dehashed)",kpi:"amb",sev:"high",vc:"amb"},
  {id:"github",ic:"💻",lab:"Fuites GitHub",sub:"secrets / code public exposé",kpi:"cy",sev:"medium",vc:"cy"}
];
function leakCatMeta(id){for(var i=0;i<LEAK_CATS.length;i++){if(LEAK_CATS[i].id===id)return LEAK_CATS[i];}return LEAK_CATS[0];}
function leakItemRow(x){
  var m=leakCatMeta(x.cat);
  var crit=x.tag==="ransomware_mention";
  var sev=crit?"critical":m.sev;
  var chipC=sev==="critical"?"":sev==="high"?"h":"m";
  var vc=sev==="critical"?"red":sev==="high"?"amb":"cy";
  var ext=x.url?'<a href="'+esc(x.url)+'" target="_blank" rel="noopener" style="margin-left:6px;color:var(--'+vc+');text-decoration:none">↗</a>':"";
  return '<div class="inc sev-'+sev+'"><div class="top">'
    +'<span class="chip '+chipC+'">'+m.ic+' '+esc((x.source||m.id).toUpperCase())+'</span>'
    +'<span class="ttl">'+esc(x.label||"—")+'</span><span class="ts">'+ago(x.ts)+ext+'</span></div>'
    +'<div class="meta">'+esc(x.msg||"")+(x.breaches?' · '+esc(x.breaches):"")+'</div></div>';
}
function renderLeaks(d){d=d||{};
  var items=d.items||[];var cats=d.cats||{};var srcs=d.sources||[];
  var total=d.total!=null?d.total:items.length;
  var bn=$("#leakSummary");
  if(bn){
    var cells=LEAK_CATS.map(function(m){
      var n=cats[m.id]!=null?cats[m.id]:0;
      return '<div class="kpi '+m.kpi+'"><div class="lab">'+m.ic+' '+esc(m.lab)+'</div>'
        +'<div class="val mono">'+(n).toLocaleString("fr")+'</div><div class="sub">'+esc(m.sub)+'</div></div>';
    });
    cells.push('<div class="kpi vio"><div class="lab">📊 Total (30 j)</div>'
      +'<div class="val mono">'+(total).toLocaleString("fr")+'</div><div class="sub">événements de fuite</div></div>');
    bn.innerHTML=cells.join("");
  }
  if($("#leakSrc"))$("#leakSrc").innerHTML=srcs.length
    ?srcs.map(function(s){return '<span class="pchip">'+esc((s.k||"?").toUpperCase())+' · '+s.n+'</span>';}).join(" ")
    :'<span class="muted">'+t("leak_none")+'</span>';
  var wrap=$("#leakCats");if(!wrap)return;
  if(!items.length){
    wrap.innerHTML='<div class="card"><div class="empty" style="padding:42px 20px">'
      +'<svg class="svi" style="width:40px;height:40px;color:var(--grn);stroke-width:1.4"><use href="#i-shield"></use></svg>'
      +'<div style="font-size:15px;font-weight:700;color:var(--grn);margin-top:8px">Aucune fuite détectée</div>'
      +'<div class="muted" style="margin-top:6px">Aucune mention d\'extorsion, d\'identifiant exposé ni de fuite GitHub sur les 30 derniers jours.</div>'
      +'</div></div>';
    return;
  }
  var html=LEAK_CATS.map(function(m){
    var rows=items.filter(function(x){return x.cat===m.id;});
    var head='<div class="card"><h3>'+m.ic+' '+esc(m.lab)+'<span class="tag">'+rows.length+' · '+esc(m.sub)+'</span></h3>';
    var body=rows.length?'<div class="feed">'+rows.map(leakItemRow).join("")+'</div>':'<div class="empty" style="padding:18px">Rien à signaler ✅</div>';
    return head+body+'</div>';
  }).join("");
  wrap.innerHTML=html;
}
function heat(n){return n===0?"h0":n<10?"h1":n<100?"h2":n<1000?"h3":"h4";}
function renderMatrix(m){m=m||[];$("#atkMatrix").innerHTML=m.map(col=>`<div class="mcol">
  <div class="mhead">${esc(col.tactic)}<span>${col.techniques.length} tech.</span></div>
  ${col.techniques.map(t=>`<div class="mcell ${heat(t.count)}" style="cursor:pointer" data-onclick="openTech('${esc(t.id)}')" title="${esc(t.id)} — ${esc(t.name)} (${t.count} évén. 7j) · cliquer pour les détections">
    <b>${esc(t.id)}</b><em>${esc(t.name)}</em>${t.count?`<i>${t.count.toLocaleString("fr")}</i>`:""}</div>`).join("")}
  </div>`).join("");}
function sevClass(s){s=(s||"").toLowerCase();return s.includes("crit")?"critical":s.includes("high")||s.includes("elev")?"high":s.includes("med")||s.includes("moy")?"medium":"low";}
const chipCls=c=>c==="high"?"h":c==="medium"?"m":c==="low"?"l":"";
const ST={new:["Nouveau","m"],in_progress:["En cours","h"],closed:["Clos","l"]};
let CASES=[];
function renderCases(list){CASES=list||[];const el=$("#incFeed");
  if(!CASES.length){el.innerHTML='<div class="empty">Aucun incident corrélé ✅</div>';return;}
  el.innerHTML=CASES.map((x,i)=>{const c=sevClass(x.severity);const s=ST[x.status]||ST.new;
    return `<div class="inc sev-${c}" data-onclick="openCase(${i})"><div class="top">
      <span class="chip ${chipCls(c)}">${esc((x.severity||'?').toUpperCase())}</span>
      <span class="ttl">${esc(x.title)}</span>
      <span class="cstat ${s[1]}">${s[0]}</span><span class="ts">${ago(x.ts)}</span>${window.glSearch?`<a class="gl" style="margin-left:8px" href="${glSearch(caseQuery(x))}" target="_blank" rel="noopener" data-onclick="event.stopPropagation()" title="Ouvrir la recherche Graylog (7 j)">Graylog ↗</a>`:""}</div>
      <div class="meta">${esc(((x.entities||'')+' · '+(x.mitre||'')).toString())}${x.assignée?' · 👤 '+esc(x.assignée):''}${x.notes&&x.notes.length?' · 📝 '+x.notes.length:''}${x.disposition?' · '+(x.disposition==='true_positive'?'<b style="color:var(--red)">✓ VP</b>':'<b style="color:var(--grn)">✕ FP</b>'):''}</div></div>`;}).join("");}
function openCase(i){const x=CASES[i];if(!x)return;
  const notes=(x.notes||[]).map(n=>`<div class="erow"><span class="ts">${esc((n.ts||'').slice(0,16).replace('T',' '))} · ${esc(n.by||'')}</span><div>${esc(n.text)}</div></div>`).join("")||'<div class="muted">Aucune note</div>';
  $("#emc").innerHTML=`<div class="grip"></div><h2>◈ ${esc(x.title)}</h2>
    <div class="muted" style="margin-bottom:12px">${esc((x.entities||'').toString())} · ${esc((x.mitre||'').toString())} · ${ago(x.ts)}</div>
    <div class="blk"><div class="lbl">Statut</div><div class="stbtns">
      ${["new","in_progress","closed"].map(s=>`<button class="stb ${x.status===s?'on':''}" data-onclick="caseAct('${x.id}','status','${s}')">${ST[s][0]}</button>`).join("")}</div></div>
    <div class="blk"><div class="lbl">Disposition · qualifié le cas (entraîne le modèle ML de réduction des faux positifs)</div><div class="stbtns">
      <button class="stb ${x.disposition==='true_positive'?'on':''}" style="${x.disposition==='true_positive'?'background:var(--red);border-color:var(--red);color:#fff':''}" data-onclick="caseAct('${x.id}','disposition','true_positive')">✓ Vrai positif</button>
      <button class="stb ${x.disposition==='false_positive'?'on':''}" style="${x.disposition==='false_positive'?'background:var(--grn);border-color:var(--grn);color:#04121a':''}" data-onclick="caseAct('${x.id}','disposition','false_positive')">✕ Faux positif</button></div></div>
    <div class="blk"><div class="lbl">Assigné à</div><input id="caseAsg" value="${esc(x.assignée||'')}" placeholder="compte AD"> <button class="stb" data-onclick="caseAct('${x.id}','assign',document.getElementById('caseAsg').value)">Assigner</button></div>
    ${x.narrative?`<div class="blk"><div class="lbl">Analyse</div><div class="emsg">${esc(x.narrative)}</div></div>`:''}
    ${x.remediation?`<div class="blk rem"><div class="lbl">Remédiation</div><div class="emsg">${esc(x.remediation)}</div></div>`:''}
    ${guidanceForMitre(x.mitre)}
    <div class="blk"><div class="lbl">Notes</div>${notes}
      <textarea id="caseNote" placeholder="Ajouter une note d'investigation…" rows="2"></textarea>
      <button class="stb" data-onclick="caseAct('${x.id}','note',document.getElementById('caseNote').value)">Ajouter la note</button></div>`;
  $("#emodal").classList.add("on");}
function caseAct(id,action,value){
  // Qualification OBLIGATOIRE avant clôture : un cas clôturé sans disposition = label perdu
  // pour le modèle ML de réduction des FP (oms-ml, bloqué faute de labels).
  if(action==="status"&&value==="closed"){
    var _cc=(CASES||[]).filter(function(c){return c.id===id;})[0];
    if(!_cc||!_cc.disposition){
      toastWarn((LANG==="en")?"Qualify the case (True / False positive) before closing — it trains the FP‑reduction model.":"Qualifie le cas (Vrai / Faux positif) avant de clôturer — ça entraîne le modèle de réduction des FP.",{title:(LANG==="en")?"Disposition required":"Qualification requise"});
      return;
    }
  }
  var CASE_MSG={status:t("case_status"),disposition:t("case_disp"),assign:t("case_assign"),note:t("case_note")};
  fetch(API+"/case",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({id:id,action:action,value:value})})
   .then(r=>{if(r.status===401)throw"auth";if(!r.ok)throw"http";return r.json();})
   .then(()=>{toastOk(CASE_MSG[action]||t("case_def"));closeEnt();loadAll();})
   .catch(e=>{if(e==="auth"){toastWarn("Session expirée — reconnexion…",{title:"Session"});setTimeout(()=>location.reload(),1100);}
     else toastErr("Échec de la mise à jour du cas. Réessayez.");});}
function renderAlerts(list){list=list||[];$("#alFeed").innerHTML=list.length?list.map(a=>{const c=a.priority==3?"critical":a.priority==2?"high":"medium";
  const fcss='background:#0c1525;border:1px solid var(--bd);border-radius:5px;padding:1px 7px;font-size:11px';
  const f=a.fields||{};const piv={user:1,src_ip:1,host:1,source:1,aruba_client_ip:1};
  const fchips=Object.keys(f).map(k=>{const v=f[k];const clk=piv[k]?` data-onclick="openEntity('${_jsq(v)}','${_jsq(v)}')" style="cursor:pointer;${fcss}" title="Dossier 360°"`:` style="${fcss}"`;
    return `<span${clk}><b style="color:var(--cy)">${esc(k)}</b> ${esc(v)}</span>`;}).join(" ");
  const ctx=fchips||(a.entity?`<span style="${fcss}">${esc(a.entity)}</span>`:"");
  return `<div class="inc sev-${c}"><div class="top"><span class="chip ${c=='high'?'h':c=='medium'?'m':''}">P${a.priority||'-'}</span>
    <span class="ttl">${esc(a.title)}</span><span class="ts">${ago(a.ts)}</span></div>
    ${ctx?`<div class="meta" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">${ctx}</div>`:""}</div>`;}).join(""):'<div class="empty">RAS</div>';}

setInterval(()=>{$("#clock")&&($("#clock").textContent=new Date().toLocaleTimeString("fr"))},1000);
document.documentElement.lang=LANG;applyI18n();updateLangBtn();
j("/me").then(d=>{if(d.user)start();}).catch(()=>{});
/* ===================== ACCESSIBILITE & CLAVIER (P3) ===================== */
(function(){
  var A11Y_SEL = ".kpi,.inc,.mcell,.pi,.entMore,.georow";
  function a11yFocusables(root){
    if(!root) return [];
    var nodes = root.querySelectorAll('a[href],a[data-p],button,input,select,textarea,[tabindex],[role="button"],[data-onclick]');
    var out = [];
    for(var i=0;i<nodes.length;i++){
      var el = nodes[i];
      if(el.disabled) continue;
      if(el.getAttribute("tabindex")==="-1") continue;
      if(el.offsetParent===null && el.tagName!=="INPUT") continue;
      out.push(el);
    }
    return out;
  }
  function a11yMakeButton(el){
    if(!el || el.dataset.a11y) return;
    var tag = el.tagName;
    if(tag==="A"||tag==="BUTTON"||tag==="INPUT"||tag==="SELECT"||tag==="TEXTAREA"){
      el.dataset.a11y = "1";
      if(tag==="A" && !el.getAttribute("href") && !el.hasAttribute("role")) el.setAttribute("role","button");
      if((tag==="A") && !el.hasAttribute("tabindex")) el.setAttribute("tabindex","0");
      return;
    }
    el.dataset.a11y = "1";
    if(!el.hasAttribute("role")) el.setAttribute("role","button");
    if(!el.hasAttribute("tabindex")) el.setAttribute("tabindex","0");
  }
  function a11yScan(root){
    if(!root) return;
    var list = root.querySelectorAll(A11Y_SEL);
    for(var i=0;i<list.length;i++) a11yMakeButton(list[i]);
    var withClick = root.querySelectorAll("[data-onclick]");
    for(var k=0;k<withClick.length;k++){ if(!withClick[k].dataset.a11y) a11yMakeButton(withClick[k]); }
  }
  function a11yInitStatic(){
    var logo = document.querySelector(".brand .logo");
    if(logo){ logo.setAttribute("role","img"); logo.setAttribute("aria-label","Logo OMNI SOC"); }
    var nav = document.getElementById("nav");
    if(nav){
      nav.setAttribute("role","navigation"); nav.setAttribute("aria-label","Navigation principale");
      var as = nav.querySelectorAll("a[data-p]");
      for(var n=0;n<as.length;n++){
        var a = as[n];
        if(!a.hasAttribute("tabindex")) a.setAttribute("tabindex","0");
        if(!a.hasAttribute("role")) a.setAttribute("role","button");
        a.setAttribute("aria-current", a.classList.contains("on") ? "page" : "false");
      }
    }
    var em = document.getElementById("emodal");
    if(em){ em.setAttribute("role","dialog"); em.setAttribute("aria-modal","true"); em.setAttribute("aria-label","Fiche détaillée"); if(!em.classList.contains("on")) em.setAttribute("aria-hidden","true"); }
    var pal = document.getElementById("pal");
    if(pal){ pal.setAttribute("role","dialog"); pal.setAttribute("aria-modal","true"); pal.setAttribute("aria-label","Recherche et navigation"); if(!pal.classList.contains("on")) pal.setAttribute("aria-hidden","true"); }
    var pin = document.getElementById("palIn");
    if(pin){ pin.setAttribute("role","combobox"); pin.setAttribute("aria-expanded","true"); pin.setAttribute("aria-autocomplete","list"); pin.setAttribute("aria-label","Rechercher une page ou une entité"); }
    var main = document.querySelector("main");
    if(main) a11yScan(main);
  }
  function a11yIsActivable(el){
    if(!el) return false;
    if(el.getAttribute("role")==="button") return true;
    if(el.hasAttribute("data-p")) return true;
    if(el.hasAttribute("data-onclick")) return true;
    return false;
  }
  document.addEventListener("keydown", function(e){
    if(e.key!=="Enter" && e.key!==" " && e.key!=="Spacebar") return;
    var t = e.target;
    var tn = t && t.tagName;
    if(tn==="INPUT"||tn==="TEXTAREA"||tn==="SELECT"||(t&&t.isContentEditable)) return;
    var el = t, hops=0;
    while(el && el!==document.body && hops<4){ if(a11yIsActivable(el)) break; el = el.parentElement; hops++; }
    if(!el || !a11yIsActivable(el)) return;
    e.preventDefault();
    el.click();
  }, true);
  function a11ySyncNav(){
    var nav = document.getElementById("nav"); if(!nav) return;
    var as = nav.querySelectorAll("a[data-p]");
    for(var i=0;i<as.length;i++) as[i].setAttribute("aria-current", as[i].classList.contains("on")?"page":"false");
  }
  document.addEventListener("click", function(e){
    var a = e.target && e.target.closest ? e.target.closest("#nav a[data-p]") : null;
    if(a) setTimeout(a11ySyncNav, 0);
  }, true);
  var A11Y_OPENER = null;
  function a11yTopModal(){
    var pal = document.getElementById("pal"); var em  = document.getElementById("emodal");
    if(pal && pal.classList.contains("on")) return pal;
    if(em && em.classList.contains("on")) return em;
    return null;
  }
  function a11yOnModalOpen(modal){
    var act = document.activeElement;
    if(!A11Y_OPENER && act && !modal.contains(act)) A11Y_OPENER = act;
    modal.setAttribute("aria-hidden","false");
    setTimeout(function(){
      if(!modal.classList.contains("on")) return;
      var pin = modal.querySelector("#palIn");
      if(pin){ try{ pin.focus(); }catch(_){ } return; }
      if(modal.contains(document.activeElement) && document.activeElement!==document.body) return;
      var f = a11yFocusables(modal.querySelector(".emc,.palbox")||modal);
      var card = modal.querySelector(".emc,.palbox");
      if(f.length){ try{ f[0].focus(); }catch(_){ } }
      else if(card){ card.setAttribute("tabindex","-1"); try{ card.focus(); }catch(_){ } }
    }, 40);
  }
  function a11yOnModalClose(modal){
    modal.setAttribute("aria-hidden","true");
    if(!a11yTopModal() && A11Y_OPENER){
      var o = A11Y_OPENER; A11Y_OPENER = null;
      setTimeout(function(){ try{ if(o && o.focus) o.focus(); }catch(_){ } }, 0);
    }
  }
  function a11yWatchModal(id){
    var m = document.getElementById(id); if(!m) return;
    var was = m.classList.contains("on");
    new MutationObserver(function(){
      var now = m.classList.contains("on");
      if(now===was) return;
      was = now;
      if(now) a11yOnModalOpen(m); else a11yOnModalClose(m);
    }).observe(m, {attributes:true, attributeFilter:["class"]});
  }
  document.addEventListener("keydown", function(e){
    if(e.key!=="Tab") return;
    var modal = a11yTopModal(); if(!modal) return;
    var scope = modal.querySelector(".emc,.palbox") || modal;
    var f = a11yFocusables(scope);
    if(!f.length){ e.preventDefault(); return; }
    var first = f[0], last = f[f.length-1], act = document.activeElement;
    if(!modal.contains(act)){ e.preventDefault(); try{ first.focus(); }catch(_){ } return; }
    if(e.shiftKey && act===first){ e.preventDefault(); try{ last.focus(); }catch(_){ } }
    else if(!e.shiftKey && act===last){ e.preventDefault(); try{ first.focus(); }catch(_){ } }
  }, true);
  function a11yBoot(){
    a11yInitStatic();
    a11yWatchModal("emodal"); a11yWatchModal("pal");
    var main = document.querySelector("main");
    if(main){
      new MutationObserver(function(muts){
        for(var i=0;i<muts.length;i++){
          var added = muts[i].addedNodes;
          for(var k=0;k<added.length;k++){
            var node = added[k];
            if(node.nodeType!==1) continue;
            if(node.matches && node.matches(A11Y_SEL+",[data-onclick]")) a11yMakeButton(node);
            a11yScan(node);
          }
        }
      }).observe(main, {childList:true, subtree:true});
      a11yScan(main);
    }
    var emc = document.getElementById("emc");
    if(emc) new MutationObserver(function(){ a11yScan(emc); }).observe(emc,{childList:true,subtree:true});
    var pl = document.getElementById("palList");
    if(pl) new MutationObserver(function(){ a11yScan(pl); }).observe(pl,{childList:true,subtree:true});
  }
  if(document.readyState==="loading") document.addEventListener("DOMContentLoaded", a11yBoot);
  else a11yBoot();
})();
