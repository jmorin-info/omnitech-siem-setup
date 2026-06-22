#!/usr/bin/env bash
# =============================================================================
# 34-weekly-report.sh - Installe/active le rapport hebdomadaire (lundi 08:00)
# Le generateur est /usr/local/sbin/omni-weekly-report (Python). Config dans
# 00-vars.env (REPORT_RECIPIENTS, REPORT_FROM, REPORT_SMTP[_PORT]).
# Idempotent. Pour un envoi immediat : systemctl start omni-weekly-report.service
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
echo "==> Detecteur omni-weekly-report (VERSIONNE ici)"
# Auparavant non versionne (binaire suppose present) -> source desormais dans le repo.
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-weekly-report <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-weekly-report - Rapport hebdomadaire SIEM OMNITECH (mail HTML)
# Lance par omni-weekly-report.timer (lundi 08:00). Config: /root/omnitech-siem-setup/00-vars.env
# Couvre les 7 derniers jours : alertes, AD, VPN, endpoint, M365, sauvegardes,
# capacite, sante collecte. Sert de preuve de revue reguliere (ISO A.5.36/A.8.16).
# Tout en ASCII (coherence avec les mails du SIEM). Robuste : une section qui
# echoue n'empeche pas l'envoi. Statut renvoye en GELF (auto-surveillance).
# =============================================================================
import json, os, re, smtplib, ssl, sys, urllib.request
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.utils import formatdate

OS_URL   = "http://127.0.0.1:9200"
GL_API   = "https://bx-it-graylog-vm.omnitech.security:9000/api"
GL_CA    = "/etc/graylog/certs/omnitech-rootca.crt"
GELF_URL = "http://127.0.0.1:12201/gelf"
DATA_FS  = "/data"

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m:
                v = m.group(2).strip().strip("'").strip('"')
                env[m.group(1)] = v
    except OSError:
        pass
    return env
ENV = load_env()

def es(path, body):
    req = urllib.request.Request(OS_URL + path,
        data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def gl(path):
    ctx = ssl.create_default_context(cafile=GL_CA)
    import base64
    auth = base64.b64encode(("admin:" + ENV.get("GRAYLOG_ADMIN_PASS","")).encode()).decode()
    req = urllib.request.Request(GL_API + path, headers={"Authorization": "Basic " + auth})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.load(r)

def count(index, query, gte="now-7d"):
    body = {"query": {"bool": {"filter": [{"range": {"timestamp": {"gte": gte}}}]}}}
    if query:
        body["query"]["bool"]["filter"].append({"query_string": {"query": query}})
    try:
        return es(f"/{index}/_count", body).get("count", 0)
    except Exception:
        return 0

def terms(index, query, field, size=10, gte="now-7d"):
    body = {"size": 0, "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": gte}}}]}},
            "aggs": {"a": {"terms": {"field": field, "size": size}}}}
    if query:
        body["query"]["bool"]["filter"].append({"query_string": {"query": query}})
    try:
        return [(b["key"], b["doc_count"]) for b in es(f"/{index}/_search", body)["aggregations"]["a"]["buckets"]]
    except Exception:
        return []

def top_sum(index, query, field, sumfield, size=10, gte="now-7d"):
    """Top N valeurs de <field> classees par SOMME de <sumfield> (ex: risk_score)."""
    body = {"size": 0, "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": gte}}}]}},
            "aggs": {"a": {"terms": {"field": field, "size": size, "order": {"s": "desc"}},
                           "aggs": {"s": {"sum": {"field": sumfield}}}}}}
    if query:
        body["query"]["bool"]["filter"].append({"query_string": {"query": query}})
    try:
        return [(b["key"], int(b["s"]["value"])) for b in es(f"/{index}/_search", body)["aggregations"]["a"]["buckets"]]
    except Exception:
        return []

# --- collecte des donnees -----------------------------------------------------
now = datetime.now(timezone.utc)
period = f"{(now-timedelta(days=7)):%d/%m/%Y} -> {now:%d/%m/%Y}"

# definitions id -> (titre, priorite)
defmap = {}
try:
    for d in gl("/events/definitions?per_page=300")["event_definitions"]:
        defmap[d["id"]] = (d["title"], d.get("priority", 0))
except Exception:
    pass

# alertes declenchees (gl-events)
alerts = terms("gl-events_*", "", "event_definition_id", size=50)
alerts_named = sorted(((defmap.get(i,(i,0))[0], defmap.get(i,(i,0))[1], n) for i,n in alerts),
                      key=lambda x: (-x[1], -x[2]))
total_alerts = sum(n for _,_,n in alerts_named)
p3 = sum(n for _,pr,n in alerts_named if pr == 3)

# AD / identite
lockouts = terms("omni-winsec_*", "event_id:4740", "user", 10)
failed_logon = count("omni-winsec_*", "event_id:4625 AND logon_fail:1")
new_accts = terms("omni-winsec_*", "event_id:4720", "user", 10)
priv_grp = count("omni-winsec_*", "_exists_:priv_group_label")

# VPN
vpn_fail = count("omni-fortigate_*", "subtype:vpn AND action:ssl\\-login\\-fail")
vpn_ips = terms("omni-fortigate_*", "subtype:vpn AND action:ssl\\-login\\-fail", "remip", 8)
vpn_ok = count("omni-fortigate_*", "subtype:vpn AND action:tunnel\\-up")

# endpoint
ps_susp = count("omni-sysmon_*,omni-winother_*", "alert_tag:powershell_suspect")
defender = count("omni-winother_*", "alert_tag:defender")

# M365
m365_foreign = count("omni-m365_*", "alert_tag:m365_etranger")
m365_signin = count("omni-m365_*", "m365_type:signin")

# sauvegardes
veeam_fail = count("omni-winother_*", "alert_tag:veeam_job_echec")
veeam_hosts = terms("omni-winother_*", "alert_tag:veeam_job_echec", "source", 10)
bkp_ok = count("graylog_*", "event_action:backup_config_ok")
bkp_fail = count("graylog_*", "event_action:backup_config_echec")

# MITRE ATT&CK + score de risque (champs poses par 37-mitre-attack.sh)
mitre_techs   = terms("omni-*", "_exists_:mitre_technique_name", "mitre_technique_name", 5)
mitre_tactics = terms("omni-*", "_exists_:mitre_tactic", "mitre_tactic", 5)
risk_hosts    = top_sum("omni-*", "_exists_:risk_score", "host", "risk_score", 5)
risk_users    = top_sum("omni-*", "_exists_:risk_score AND _exists_:user", "user", "risk_score", 5)
crit_detn     = count("omni-*", "risk_severity:critique")

# capacite
def disk():
    try:
        st = os.statvfs(DATA_FS)
        total = st.f_blocks * st.f_frsize; free = st.f_bavail * st.f_frsize
        used = total - free
        return used/total*100, used/1e12, total/1e12
    except Exception:
        return 0,0,0
disk_pct, disk_used_tb, disk_tot_tb = disk()
idx_sizes = []
try:
    raw = urllib.request.urlopen(OS_URL + "/_cat/indices/omni-*?h=index,store.size,docs.count&bytes=b", timeout=15).read().decode()
    agg = {}
    for line in raw.splitlines():
        p = line.split()
        if len(p) >= 2:
            prefix = p[0].rsplit("_",1)[0]
            agg[prefix] = agg.get(prefix,0) + int(p[1])
    idx_sizes = sorted(agg.items(), key=lambda x:-x[1])
except Exception:
    pass

# sante collecte
hosts_active = len(terms("omni-winsec_*,omni-sysmon_*,omni-winother_*", "", "source", 200, gte="now-24h"))
try:
    idx_fail = gl("/system/indexer/failures?limit=1&offset=0").get("total", 0)
except Exception:
    idx_fail = "?"

# --- rendu HTML ---------------------------------------------------------------
def rows(data, cols=("", "")):
    if not data: return '<tr><td colspan="2" style="padding:6px;color:#868e96">aucun</td></tr>'
    return "".join(f'<tr><td style="padding:5px 8px;border-bottom:1px solid #eee">{k}</td>'
                   f'<td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right"><b>{v}</b></td></tr>'
                   for k,v in data)
def kpi(label, val, color="#1c2333"):
    return (f'<td style="padding:10px;text-align:center;border:1px solid #e6e9ee;border-radius:6px">'
            f'<div style="font-size:24px;font-weight:700;color:{color}">{val}</div>'
            f'<div style="font-size:11px;color:#868e96;text-transform:uppercase;letter-spacing:.5px">{label}</div></td>')

alert_rows = "".join(
    f'<tr><td style="padding:5px 8px;border-bottom:1px solid #eee">{"P%d "%pr}{t}</td>'
    f'<td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right"><b>{n}</b></td></tr>'
    for t,pr,n in alerts_named[:15]) or '<tr><td colspan=2 style="padding:6px;color:#868e96">aucune alerte</td></tr>'

cap_rows = "".join(
    f'<tr><td style="padding:5px 8px;border-bottom:1px solid #eee">{p}</td>'
    f'<td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right">{s/1e9:.1f} Go</td></tr>'
    for p,s in idx_sizes)

bkp_color = "#2b8a3e" if bkp_fail == 0 and bkp_ok >= 6 else "#e8590c"
veeam_color = "#2b8a3e" if veeam_fail == 0 else "#e03131"
disk_color = "#2b8a3e" if disk_pct < 80 else "#e8590c"

html = f"""<!doctype html><html><body style="margin:0;background:#eef1f4">
<div style="max-width:820px;margin:16px auto;font-family:'Segoe UI',Arial,sans-serif;background:#fff;border:1px solid #dde3ea;border-radius:8px;overflow:hidden">
  <div style="background:#1c2333;padding:18px 24px;border-bottom:4px solid #1971c2">
    <div style="font-size:11px;letter-spacing:2px;color:#8ea2c9;text-transform:uppercase">SIEM OMNITECH - Rapport hebdomadaire de supervision</div>
    <div style="font-size:20px;font-weight:600;color:#fff;margin-top:3px">Semaine {period}</div>
  </div>
  <div style="padding:18px 24px">
    <table style="width:100%;border-collapse:separate;border-spacing:6px"><tr>
      {kpi("Alertes (7j)", total_alerts)}
      {kpi("dont P3", p3, "#c2255c")}
      {kpi("Echecs AD", failed_logon)}
      {kpi("Echecs VPN", vpn_fail)}
      {kpi("Disque /data", f"{disk_pct:.0f}%", disk_color)}
    </tr></table>

    <h3 style="font-size:14px;color:#1c2333;margin:18px 0 6px">Alertes declenchees</h3>
    <table style="width:100%;border-collapse:collapse;font-size:13px">{alert_rows}</table>

    <h3 style="font-size:14px;color:#1c2333;margin:18px 0 6px">Menaces &amp; risque - MITRE ATT&amp;CK (7j)</h3>
    <table style="width:100%"><tr>
      <td style="width:50%;vertical-align:top;padding-right:8px">
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <tr><td colspan="2" style="padding:4px 8px;color:#868e96;font-size:11px;text-transform:uppercase">Top techniques observees</td></tr>
          {rows([(str(t), n) for t,n in mitre_techs])}
          <tr><td colspan="2" style="padding:4px 8px;color:#868e96;font-size:11px;text-transform:uppercase">Top tactiques</td></tr>
          {rows([(str(t), n) for t,n in mitre_tactics])}
        </table>
      </td>
      <td style="width:50%;vertical-align:top;padding-left:8px">
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">Detections critiques (7j)</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right;color:{'#e03131' if crit_detn else '#2b8a3e'}"><b>{crit_detn}</b></td></tr>
          <tr><td colspan="2" style="padding:4px 8px;color:#868e96;font-size:11px;text-transform:uppercase">Hotes au plus haut score de risque</td></tr>
          {rows([(str(h), s) for h,s in risk_hosts])}
          <tr><td colspan="2" style="padding:4px 8px;color:#868e96;font-size:11px;text-transform:uppercase">Comptes au plus haut score</td></tr>
          {rows([(str(u), s) for u,s in risk_users])}
        </table>
      </td>
    </tr></table>

    <table style="width:100%;margin-top:6px"><tr>
      <td style="width:50%;vertical-align:top;padding-right:8px">
        <h3 style="font-size:14px;color:#1c2333;margin:18px 0 6px">Identite / AD</h3>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">Echecs d'authentification (humains)</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right"><b>{failed_logon}</b></td></tr>
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">Modifs de groupes privilegies</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right"><b>{priv_grp}</b></td></tr>
          {rows([("Verrou.: "+str(u), n) for u,n in lockouts[:5]])}
          {rows([("Cree: "+str(u), n) for u,n in new_accts[:5]])}
        </table>
      </td>
      <td style="width:50%;vertical-align:top;padding-left:8px">
        <h3 style="font-size:14px;color:#1c2333;margin:18px 0 6px">VPN / Exposition</h3>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">Tunnels legitimes montes</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right"><b>{vpn_ok}</b></td></tr>
          {rows([("Attaque: "+str(ip), n) for ip,n in vpn_ips[:6]])}
        </table>
      </td>
    </tr></table>

    <table style="width:100%"><tr>
      <td style="width:50%;vertical-align:top;padding-right:8px">
        <h3 style="font-size:14px;color:#1c2333;margin:18px 0 6px">Endpoint / Cloud</h3>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">PowerShell suspect</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right"><b>{ps_susp}</b></td></tr>
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">Defender (detections/desactiv.)</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right"><b>{defender}</b></td></tr>
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">M365 connexions hors France</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right"><b>{m365_foreign}</b></td></tr>
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">M365 connexions totales</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right">{m365_signin}</td></tr>
        </table>
      </td>
      <td style="width:50%;vertical-align:top;padding-left:8px">
        <h3 style="font-size:14px;color:#1c2333;margin:18px 0 6px">Sauvegardes</h3>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">Backup config SIEM (OK / echec)</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right;color:{bkp_color}"><b>{bkp_ok} / {bkp_fail}</b></td></tr>
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">Jobs Veeam en echec/avert.</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right;color:{veeam_color}"><b>{veeam_fail}</b></td></tr>
          {rows([("  -> "+str(h), n) for h,n in veeam_hosts[:5]])}
        </table>
      </td>
    </tr></table>

    <table style="width:100%"><tr>
      <td style="width:50%;vertical-align:top;padding-right:8px">
        <h3 style="font-size:14px;color:#1c2333;margin:18px 0 6px">Capacite (par flux, 7j cumules en index)</h3>
        <table style="width:100%;border-collapse:collapse;font-size:13px">{cap_rows}
          <tr><td style="padding:5px 8px;border-top:2px solid #dde3ea">/data utilise</td><td style="padding:5px 8px;border-top:2px solid #dde3ea;text-align:right;color:{disk_color}"><b>{disk_used_tb:.2f} / {disk_tot_tb:.1f} To ({disk_pct:.0f}%)</b></td></tr>
        </table>
      </td>
      <td style="width:50%;vertical-align:top;padding-left:8px">
        <h3 style="font-size:14px;color:#1c2333;margin:18px 0 6px">Sante de la collecte</h3>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">Hotes actifs (24h)</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right"><b>{hosts_active}</b></td></tr>
          <tr><td style="padding:5px 8px;border-bottom:1px solid #eee">Echecs d'indexation (total courant)</td><td style="padding:5px 8px;border-bottom:1px solid #eee;text-align:right;color:{'#2b8a3e' if idx_fail in (0,'0') else '#e8590c'}"><b>{idx_fail}</b></td></tr>
        </table>
      </td>
    </tr></table>

    <div style="margin-top:18px;padding:10px;background:#f8f9fa;border-radius:6px;font-size:12px;color:#495057">
      <b>A verifier cette semaine</b> : hotes au plus haut score de risque (ATT&amp;CK) ci-dessus, alertes P3 non qualifiees, jobs Veeam en echec, comptes crees/verrouilles inattendus, derive de capacite.
      Procedure : OMNI - SOC (console) + PRO-EXPLOITATION-SIEM.
    </div>
  </div>
  <div style="background:#f8f9fa;color:#adb5bd;font-size:11px;padding:10px 24px">Rapport automatique - SIEM OMNITECH Security - genere le {now:%d/%m/%Y %H:%M} UTC. Preuve de revue (ISO 27001 A.5.36 / A.8.16).</div>
</div></body></html>"""

# --- envoi --------------------------------------------------------------------
def gelf(action, msg):
    try:
        data = json.dumps({"version":"1.1","host":"bx-it-graylog-vm",
            "short_message":"rapport hebdo: "+msg,"_event_source":"siem_report","_event_action":action}).encode()
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=data,
            headers={"Content-Type":"application/json"}), timeout=10)
    except Exception:
        pass

# copie locale systematique (preuve de revue / consultation hors mail)
try:
    open(f"/var/backups/siem/rapport-hebdo_{now:%Y-%m-%d}.html", "w").write(html)
except Exception:
    pass

recipients = [r.strip() for r in ENV.get("REPORT_RECIPIENTS","informatique@omnitech-security.fr").split(",")]
msg = MIMEText(html, "html", "utf-8")
msg["Subject"] = f"[SIEM] Rapport hebdomadaire de supervision - {now:%d/%m/%Y}"
msg["From"] = ENV.get("REPORT_FROM","no-reply@omnitech-security.fr")
msg["To"] = ", ".join(recipients)
msg["Date"] = formatdate(localtime=True)

try:
    with smtplib.SMTP(ENV.get("REPORT_SMTP","smtp-internal.omnitech-security.fr"),
                      int(ENV.get("REPORT_SMTP_PORT","25")), timeout=30) as s:
        s.sendmail(msg["From"], recipients, msg.as_string())
    gelf("report_ok", f"{total_alerts} alertes, {p3} P3, disque {disk_pct:.0f}%")
    print(f"OK rapport envoye a {recipients} ({total_alerts} alertes, {p3} P3)")
except Exception as e:
    gelf("report_echec", str(e)[:150])
    # archive locale de secours
    out = f"/var/backups/siem/rapport-hebdo_{now:%Y-%m-%d}.html"
    try: open(out,"w").write(html); print(f"ECHEC envoi ({e}) - rapport sauve dans {out}", file=sys.stderr)
    except Exception: pass
    sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-weekly-report
systemctl daemon-reload
systemctl enable --now omni-weekly-report.timer
echo "[+] timer omni-weekly-report actif :"
systemctl list-timers omni-weekly-report.timer --no-pager | sed -n '1,2p'
echo "Envoi immediat de test : systemctl start omni-weekly-report.service ; journalctl -u omni-weekly-report -n 20"
