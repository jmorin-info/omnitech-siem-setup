#!/usr/bin/env bash
# 45-monthly-report.sh - Rapport executif mensuel (HTML + PDF weasyprint, email).
#   Timer le 1er du mois a 06:00. Archive sous /var/www/siem-kit/rapports/.
set -euo pipefail
cd "$(dirname "$0")"; source ./00-vars.env
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }
echo "==> Detecteur omni-monthly-report (VERSIONNE ici)"
# Auparavant non versionne (binaire suppose present) -> source desormais dans le repo.
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-monthly-report <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-monthly-report - Rapport executif MENSUEL (posture, incidents, UEBA,
#   carte des menaces, conformite/capacite). HTML auto-suffisant calibre A4
#   (Imprimer -> PDF en 1 clic), archive sous /var/www/siem-kit/rapports/ et
#   envoye par mail. Embarque une carte SVG des menaces (30 j). Zero dependance.
# Lance par timer le 1er du mois. Config SMTP : REPORT_* dans 00-vars.env.
# =============================================================================
import json, math, os, re, smtplib, ssl, subprocess, sys, urllib.request
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

WEASYPRINT = "/opt/omni-venv/bin/weasyprint"   # vrai PDF (HTML->PDF, SVG+CSS)

OS_URL = "http://127.0.0.1:9200"
ARCHIVE = "/var/www/siem-kit/rapports"

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
ENV = load_env()

def es(idx, body):
    req = urllib.request.Request(f"{OS_URL}/{idx}/_search", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def count(idx, q):
    try:
        req = urllib.request.Request(f"{OS_URL}/{idx}/_count", data=json.dumps({"query": q}).encode(),
                                     headers={"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=30))["count"]
    except Exception:
        return 0

def terms(idx, field, q, size=10, sub=None):
    aggs = {"t": {"terms": {"field": field, "size": size}}}
    if sub: aggs["t"]["aggs"] = sub
    try:
        return es(idx, {"size": 0, "query": q, "aggs": aggs})["aggregations"]["t"]["buckets"]
    except Exception:
        return []

M = lambda d: {"range": {"timestamp": {"gte": f"now-{d}"}}}
def AND(*qs): return {"bool": {"must": list(qs)}}
def cardv(idx, field, q):
    try:
        return es(idx, {"size":0,"query":q,"aggs":{"c":{"cardinality":{"field":field}}}})["aggregations"]["c"]["value"]
    except Exception:
        return 0

# ---------------------------------------------------------------- carte SVG 30j
def threat_map_svg(w=900, h=450):
    proj = lambda lat, lon: ((lon+180)/360*w, (90-lat)/180*h)
    try:
        world = json.load(open("/var/www/siem-kit/carte-world.geojson"))
    except Exception:
        return "<p style='color:#888'>(fond de carte indisponible)</p>"
    hq = (float(ENV.get("GEO_HQ_LAT","44.88")), float(ENV.get("GEO_HQ_LON","-0.55")))
    # deny geolocalises sur 30j, agreges par geoloc
    flows = []
    for b in terms("omni-fortigate_*", "src_ip_geolocation",
                   AND(M("30d"), {"term":{"action":"deny"}}, {"exists":{"field":"src_ip_geolocation"}}), size=400):
        try: lat, lon = map(float, b["key"].split(","))
        except Exception: continue
        if abs(lat-hq[0])<1 and abs(lon-hq[1])<1: continue
        flows.append((lat, lon, b["doc_count"]))
    flows.sort(key=lambda x:-x[2]); flows = flows[:120]
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">']
    out.append(f'<rect width="{w}" height="{h}" fill="#0c1422"/>')
    for f in world.get("features", []):
        g = f.get("geometry");
        if not g: continue
        polys = [g["coordinates"]] if g["type"]=="Polygon" else g["coordinates"] if g["type"]=="MultiPolygon" else []
        for poly in polys:
            d = ""
            for ring in poly:
                if len(ring) < 4:
                    continue
                pts = " ".join(f"{proj(c[1],c[0])[0]:.1f},{proj(c[1],c[0])[1]:.1f}" for c in ring[::2])
                d += f"M{pts}Z"
            out.append(f'<path d="{d}" fill="#16243a" fill-rule="evenodd" stroke="#2b425a" stroke-width=".4"/>')
    ex, ey = proj(*hq)
    for lat, lon, c in flows:
        sx, sy = proj(lat, lon); dx, dy = ex-sx, ey-sy; dist = math.hypot(dx,dy)
        cx, cy = (sx+ex)/2 - dy*0.22, (sy+ey)/2 + dx*0.22 - dist*0.12
        wdt = min(2.6, 0.4+math.log10(c+1)*0.7)
        out.append(f'<path d="M{sx:.1f},{sy:.1f} Q{cx:.1f},{cy:.1f} {ex:.1f},{ey:.1f}" fill="none" stroke="#e09f3e" stroke-width="{wdt:.1f}" stroke-opacity=".5"/>')
        out.append(f'<circle cx="{sx:.1f}" cy="{sy:.1f}" r="1.8" fill="#e09f3e"/>')
    out.append(f'<circle cx="{ex:.1f}" cy="{ey:.1f}" r="5" fill="#36d399"/><circle cx="{ex:.1f}" cy="{ey:.1f}" r="11" fill="none" stroke="#36d399" stroke-width="1.5" stroke-opacity=".5"/>')
    out.append("</svg>")
    return "\n".join(out)

# ---------------------------------------------------------------------- donnees
def gather():
    d = {}
    allidx = "omni-*"
    d["events"]      = count(allidx, M("30d"))
    d["detections"]  = count(allidx, AND(M("30d"), {"exists":{"field":"alert_tag"}}))
    d["hosts"]       = cardv(allidx, "host", M("30d"))
    d["deny"]        = count("omni-fortigate_*", AND(M("30d"), {"term":{"action":"deny"}}))
    # incidents (dernier passage) -- evenements INT -> index par defaut graylog_*
    # (JAMAIS un numero en dur : le deflector tourne, graylog_0 finit en 404)
    INT_IDX = "graylog_*"
    d["inc_crit"]    = cardv(INT_IDX, "incident_entity", AND(M("35m"), {"term":{"event_source":"incident"}}, {"term":{"incident_severity":"critique"}}))
    d["inc_high"]    = cardv(INT_IDX, "incident_entity", AND(M("35m"), {"term":{"event_source":"incident"}}, {"term":{"incident_severity":"eleve"}}))
    d["incidents"]   = []
    for b in es(INT_IDX, {"size":8, "query":AND(M("35m"), {"term":{"event_source":"incident"}}),
                "sort":[{"incident_score":"desc"}],
                "_source":["incident_severity","incident_entity","incident_score","incident_tactics","incident_kill_chain","incident_span_h"]})["hits"]["hits"]:
        d["incidents"].append(b["_source"])
    # UEBA top (dernier passage)
    d["ueba"] = {"host":[], "user":[]}
    for et in ("host","user"):
        for b in es(INT_IDX, {"size":8, "query":AND(M("35m"), {"term":{"event_source":"ueba_score"}}, {"term":{"entity_type":et}}),
                    "sort":[{"ueba_score":"desc"}], "_source":["ueba_entity","ueba_score","ueba_top_factor"]})["hits"]["hits"]:
            d["ueba"][et].append(b["_source"])
    # MITRE
    d["techniques"]  = cardv("omni-*", "mitre_technique", AND(M("30d"), {"exists":{"field":"mitre_technique"}}))
    d["tactics"]     = [(b["key"], b["doc_count"]) for b in terms("omni-*","mitre_tactic", AND(M("30d"),{"exists":{"field":"mitre_tactic"}}), size=14)]
    # collecte / vuln
    sla = es(INT_IDX, {"size":1,"query":AND(M("2h"),{"term":{"event_source":"collecte_sla"}},{"term":{"sla_type":"summary"}}),"sort":[{"timestamp":"desc"}],"_source":["sla_coverage_pct","sla_expected","sla_go_dark"]})["hits"]["hits"]
    d["sla"] = sla[0]["_source"] if sla else {}
    d["vuln_kev"]    = cardv(INT_IDX, "host", AND(M("7d"), {"term":{"event_source":"vuln"}}, {"term":{"vuln_type":"kev"}}))
    # capacite (taille disque / docs)
    try:
        cat = json.load(urllib.request.urlopen(f"{OS_URL}/_cat/indices/omni-*?format=json&bytes=b", timeout=20))
        store = sum(int(i["store.size"]) for i in cat); docs = sum(int(i["docs.count"]) for i in cat)
        last24 = count("omni-*", M("1d"))
        d["gb_day"] = round((store/docs if docs else 0)*last24/1e9, 1)
        d["store_tb"] = round(store/1e12, 2)
    except Exception:
        d["gb_day"] = d["store_tb"] = 0
    return d

# ------------------------------------------------------------------------- HTML
def build_html(d, period):
    sevcol = {"critique":"#d64550","eleve":"#e09f3e","moyen":"#e6c200"}
    def kpi(val, lbl, col="#1f6feb"):
        return f'<div class="kpi"><div class="v" style="color:{col}">{val}</div><div class="l">{lbl}</div></div>'
    inc_rows = "".join(
        f'<tr><td><span class="pill" style="background:{sevcol.get(i.get("incident_severity"),"#888")}">{i.get("incident_severity","")}</span></td>'
        f'<td><b>{i.get("incident_entity","")}</b></td><td class="num">{i.get("incident_score","")}/100</td>'
        f'<td class="num">{i.get("incident_tactics","")}</td><td class="chain">{i.get("incident_kill_chain","")}</td></tr>'
        for i in d["incidents"]) or '<tr><td colspan="5" class="muted">Aucun incident correle sur la periode.</td></tr>'
    def ueba_rows(lst):
        return "".join(f'<tr><td><b>{u.get("ueba_entity","")}</b></td><td class="num">{u.get("ueba_score","")}</td>'
                       f'<td class="muted">{u.get("ueba_top_factor","")}</td></tr>' for u in lst) or '<tr><td colspan="3" class="muted">-</td></tr>'
    tac_rows = "".join(f'<tr><td>{t}</td><td class="num">{c}</td></tr>' for t,c in d["tactics"]) or '<tr><td colspan="2" class="muted">-</td></tr>'
    sla = d.get("sla",{})
    cov = sla.get("sla_coverage_pct","--")
    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>Rapport SOC {period}</title>
<style>
  @page{{size:A4;margin:14mm}}
  *{{box-sizing:border-box}} body{{font-family:"Segoe UI",system-ui,sans-serif;color:#1a2433;margin:0;background:#f4f6f9}}
  .wrap{{max-width:1000px;margin:0 auto;padding:0 8px}}
  header{{background:linear-gradient(120deg,#0b1f3a,#16345e);color:#fff;padding:26px 30px;border-radius:0 0 4px 4px}}
  header h1{{margin:0;font-size:24px;letter-spacing:.3px}} header .sub{{opacity:.8;margin-top:5px;font-size:13px}}
  header .brand{{font-size:12px;letter-spacing:3px;text-transform:uppercase;opacity:.7}}
  section{{background:#fff;margin:14px 0;border:1px solid #e3e8f0;border-radius:8px;padding:18px 22px;page-break-inside:avoid}}
  h2{{font-size:15px;margin:0 0 14px;color:#0b2748;border-left:4px solid #1f6feb;padding-left:10px}}
  .kpis{{display:flex;flex-wrap:wrap;gap:12px}}
  .kpi{{flex:1;min-width:130px;background:#f7f9fc;border:1px solid #e3e8f0;border-radius:8px;padding:14px;text-align:center}}
  .kpi .v{{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}} .kpi .l{{font-size:11px;color:#5b6b82;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
  table{{width:100%;border-collapse:collapse;font-size:12.5px}}
  th{{text-align:left;color:#5b6b82;font-weight:600;border-bottom:2px solid #e3e8f0;padding:6px 8px;font-size:11px;text-transform:uppercase}}
  td{{padding:6px 8px;border-bottom:1px solid #eef1f6;vertical-align:top}} .num{{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}}
  .chain{{font-size:11px;color:#33465f}} .muted{{color:#8595a8}} .pill{{color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;text-transform:uppercase;letter-spacing:.5px}}
  .cols{{display:flex;gap:14px;flex-wrap:wrap}} .cols>div{{flex:1;min-width:260px}}
  .map{{text-align:center}} .map svg{{max-width:100%;height:auto;border-radius:6px}}
  footer{{text-align:center;color:#8595a8;font-size:11px;padding:18px}}
  .good{{color:#1a8a4f}} .warn{{color:#c8821a}}
</style></head><body><div class="wrap">
<header>
  <div class="brand">OMNITECH Security &middot; SOC</div>
  <h1>Rapport executif de securite</h1>
  <div class="sub">Periode : {period} &middot; genere le {datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M UTC')}</div>
</header>

<section><h2>Posture de securite (30 jours)</h2><div class="kpis">
  {kpi(f"{d['events']:,}".replace(',',' '), "Evenements collectes")}
  {kpi(f"{d['detections']:,}".replace(',',' '), "Detections", "#e09f3e")}
  {kpi(d['inc_crit'], "Incidents critiques", "#d64550")}
  {kpi(d['inc_high'], "Incidents eleves", "#e09f3e")}
  {kpi(d['hosts'], "Hotes vus")}
  {kpi(f"{cov}%", "Couverture collecte", "#1a8a4f")}
</div></section>

<section><h2>Incidents marquants &mdash; chaines d'attaque correlees</h2>
<table><tr><th>Severite</th><th>Entite</th><th>Score</th><th>Tactiques</th><th>Kill-chain ATT&amp;CK (ordonnee)</th></tr>
{inc_rows}</table></section>

<section class="map"><h2>Geographie des menaces &mdash; trafic refuse (30 jours)</h2>
{threat_map_svg()}
<div class="muted" style="margin-top:8px">Arcs : origines geographiques des connexions bloquees par le pare-feu, vers l'infrastructure (point vert).</div>
</section>

<section><div class="cols">
  <div><h2>Top hotes a risque (UEBA)</h2><table><tr><th>Hote</th><th>Score</th><th>Facteur</th></tr>{ueba_rows(d['ueba']['host'])}</table></div>
  <div><h2>Top comptes a risque (UEBA)</h2><table><tr><th>Compte</th><th>Score</th><th>Facteur</th></tr>{ueba_rows(d['ueba']['user'])}</table></div>
</div></section>

<section><div class="cols">
  <div><h2>Couverture ATT&amp;CK ({d['techniques']} techniques)</h2><table><tr><th>Tactique</th><th>Detections</th></tr>{tac_rows}</table></div>
  <div><h2>Sante &amp; conformite</h2><table>
    <tr><td>Couverture collecte (SLA)</td><td class="num good">{cov}%</td></tr>
    <tr><td>Hotes go-dark (silencieux)</td><td class="num">{sla.get('sla_go_dark','--')}</td></tr>
    <tr><td>Hotes exposes (CVE exploitee KEV)</td><td class="num warn">{d['vuln_kev']}</td></tr>
    <tr><td>Volume journalier (sur disque)</td><td class="num">{d['gb_day']} Go/j</td></tr>
    <tr><td>Donnees indexees</td><td class="num">{d['store_tb']} To</td></tr>
    <tr><td>Retention dossier securite</td><td class="num">365 jours</td></tr>
  </table></div>
</div></section>

<footer>Document genere automatiquement par le SIEM OMNITECH &middot; CONFIDENTIEL &middot; Imprimer &gt; Enregistrer au format PDF</footer>
</div></body></html>"""

MOIS_FR = ["", "janvier", "fevrier", "mars", "avril", "mai", "juin", "juillet",
           "aout", "septembre", "octobre", "novembre", "decembre"]

def main():
    now = datetime.now(timezone.utc)
    last = now.replace(day=1) - timedelta(days=1)         # dernier jour du mois ecoule
    period = f"{MOIS_FR[last.month]} {last.year}"          # ex. "mai 2026" (independant de la locale)
    d = gather()
    html = build_html(d, period)
    os.makedirs(ARCHIVE, exist_ok=True)
    fn = os.path.join(ARCHIVE, f"rapport-{(now.replace(day=1)-timedelta(days=1)).strftime('%Y-%m')}.html")
    open(fn, "w").write(html); os.chmod(fn, 0o644)
    print(f"[monthly-report] {fn} ({len(html)//1024} Ko) - incidents={len(d['incidents'])} crit={d['inc_crit']}")
    # vrai PDF via weasyprint (HTML -> PDF, rend SVG + CSS @page A4)
    pdf = fn[:-5] + ".pdf"
    if os.path.exists(WEASYPRINT):
        try:
            subprocess.run([WEASYPRINT, fn, pdf], check=True, timeout=180,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.chmod(pdf, 0o644)
            print(f"  PDF: {pdf} ({os.path.getsize(pdf)//1024} Ko)")
        except Exception as e:
            print(f"  PDF KO ({e}) -> repli HTML", file=sys.stderr); pdf = None
    else:
        pdf = None
    # envoi mail (PDF en piece jointe si dispo, sinon HTML inline)
    to = ENV.get("REPORT_RECIPIENTS",""); host = ENV.get("REPORT_SMTP",""); port = int(ENV.get("REPORT_SMTP_PORT","25"))
    if to and host and not os.environ.get("REPORT_NOMAIL"):
        try:
            msg = MIMEMultipart("mixed")
            msg["Subject"] = f"[OMNITECH SOC] Rapport executif - {period}"
            msg["From"] = ENV.get("REPORT_FROM","no-reply@omnitech-security.fr"); msg["To"] = to
            body = MIMEMultipart("alternative")
            body.attach(MIMEText(f"Rapport executif SOC - {period}. PDF en piece jointe.", "plain"))
            body.attach(MIMEText(html, "html"))
            msg.attach(body)
            if pdf:
                with open(pdf, "rb") as f:
                    att = MIMEApplication(f.read(), _subtype="pdf")
                att.add_header("Content-Disposition", "attachment", filename=os.path.basename(pdf))
                msg.attach(att)
            with smtplib.SMTP(host, port, timeout=30) as s:
                s.sendmail(msg["From"], [a.strip() for a in to.split(",")], msg.as_string())
            print(f"  mail envoye -> {to}" + (" (+ PDF)" if pdf else ""))
        except Exception as e:
            print(f"  mail KO: {e}", file=sys.stderr)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-monthly-report KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-monthly-report
cat > /etc/systemd/system/omni-monthly-report.service <<'EOF'
[Unit]
Description=OMNI SIEM - rapport executif mensuel (PDF)
After=network-online.target graylog-server.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-monthly-report
Nice=15
EOF
cat > /etc/systemd/system/omni-monthly-report.timer <<'EOF'
[Unit]
Description=OMNI SIEM - rapport mensuel (1er du mois 06:00)
[Timer]
OnCalendar=*-*-01 06:00:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-monthly-report.timer >/dev/null 2>&1 || true
echo "    [+] timer mensuel actif"
systemctl list-timers omni-monthly-report.timer --no-pager | sed -n '2p'
echo "=== 45 termine. Archive + servi : https://${SIEM_FQDN}/kit/rapports/ ==="
