#!/usr/bin/env bash
# =============================================================================
# 44-incidents.sh - Active la correlation attack-chain -> incidents
#   1. route event_source=incident -> "OMNI - Interne SIEM" (+ exclusion M365)
#   2. timer systemd (toutes les 15 min) + premier passage
#   Le correlateur /usr/local/sbin/omni-incident-correlate agrege les detections
#   MITRE par entite et reconstruit la kill-chain. Pas de mapping MITRE (les
#   evenements incident portent incident_score, pas d'alert_tag).
# Idempotent. Prerequis : 21 + 37 (enrichissement MITRE). Relance 14 + 13 ensuite.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
echo "==> Detecteur omni-incident-correlate (VERSIONNE ici)"
# Auparavant non versionne (binaire suppose present) -> source desormais dans le repo.
install -d /usr/local/sbin
cat > /usr/local/sbin/omni-incident-correlate <<'NDREOF'
#!/usr/bin/env python3
# =============================================================================
# omni-incident-correlate - Correlation attack-chain -> INCIDENTS horodates.
#   Au-dela de Graylog : agrege par ENTITE (hote/compte) les detections MITRE
#   d'une fenetre, reconstruit la KILL-CHAIN ordonnee dans le temps (ex.
#   Credential Access -> Lateral Movement -> Exfiltration) et score l'incident.
#   Un incident = >=2 TACTIQUES ATT&CK distinctes sur la meme entite. Transforme
#   des alertes eparses en un recit d'attaque exploitable (ce que l'agregation
#   Graylog ne sait pas faire). Inclut les detections comportementales (beaconing,
#   tunneling DNS, impossible travel) deja mappees MITRE.
#   Emet GELF event_source=incident (entity, kill_chain, incident_score 0-100).
# Lance par timer (toutes les 15 min). Fenetre INCIDENT_WINDOW_H (24).
# =============================================================================
import json, math, os, re, sys, urllib.request
from datetime import datetime, timezone

OS_URL = "http://127.0.0.1:9200"
GELF_URL = "http://127.0.0.1:12201/gelf"
SIEM = "bx-it-graylog-vm"

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
ENV = load_env()
WINDOW_H = int(ENV.get("INCIDENT_WINDOW_H", "24"))
MIN_TACTICS = int(ENV.get("INCIDENT_MIN_TACTICS", "2"))
K = float(ENV.get("INCIDENT_K", "30"))           # saturation du score 0-100

# Ordre canonique de la kill-chain ATT&CK (pour presenter la progression)
CHAIN = ["Reconnaissance", "Resource Development", "Initial Access", "Execution",
         "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
         "Discovery", "Lateral Movement", "Collection", "Command and Control",
         "Exfiltration", "Impact"]
ORD = {t: i for i, t in enumerate(CHAIN)}

def es(idx, body):
    req = urllib.request.Request(f"{OS_URL}/{idx}/_search", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def gelf(fields):
    if os.environ.get("UEBA_DRY"):
        return
    base = {"version": "1.1", "host": SIEM, "short_message": fields.get("short_message", "incident")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def saturate(raw):
    return round(100 * (1 - math.exp(-raw / K))) if raw > 0 else 0

def severity(score):
    return "critique" if score >= 70 else "eleve" if score >= 40 else "moyen"

# Anti-spam : on ne re-emet PAS le meme incident (meme entite + meme jeu de
# tactiques) avant REEMIT_H heures. Sans cela, le scan 15 min sur fenetre 24 h
# re-emettait ~96x/jour le meme incident. Une nouvelle tactique (escalade) ou
# l'expiration du cooldown declenchent une nouvelle emission.
STATE = ENV.get("INCIDENT_STATE", "/var/lib/omni-siem/incident-seen.json")
REEMIT_H = float(ENV.get("INCIDENT_REEMIT_H", "12"))

def load_state():
    try: return json.load(open(STATE))
    except Exception: return {}

def save_state(st):
    try:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        json.dump(st, open(STATE, "w"))
    except Exception as e:
        print("state KO:", e, file=sys.stderr)

def correlate(entity_field):
    rng = {"range": {"timestamp": {"gte": f"now-{WINDOW_H}h"}}}
    body = {"size": 0, "query": {"bool": {"must": [rng,
              {"exists": {"field": "mitre_tactic"}}, {"exists": {"field": entity_field}}]}},
        "aggs": {"e": {"terms": {"field": entity_field, "size": 500},
            "aggs": {"tac": {"terms": {"field": "mitre_tactic", "size": 20},
                "aggs": {"sev": {"max": {"field": "risk_score"}},
                         "first": {"min": {"field": "timestamp"}},
                         "last": {"max": {"field": "timestamp"}},
                         "tech": {"terms": {"field": "mitre_technique", "size": 5}},
                         "tag": {"terms": {"field": "alert_tag", "size": 5}}}}}}}}
    out = []
    for eb in es("omni-*", body)["aggregations"]["e"]["buckets"]:
        ent = eb["key"]
        tactics = eb["tac"]["buckets"]
        if len(tactics) < MIN_TACTICS:
            continue
        stages = []
        raw = 0.0
        for tb in tactics:
            tac = tb["key"]
            sev = tb["sev"]["value"] or 0
            raw += sev
            stages.append({
                "tactic": tac, "severity": sev,
                "first": tb["first"]["value_as_string"],
                "tech": ",".join(t["key"] for t in tb["tech"]["buckets"]),
                "tags": ",".join(t["key"] for t in tb["tag"]["buckets"])})
        # bonus diversite : +3 par tactique distincte au-dela de la 1ere
        raw += 3 * (len(tactics) - 1)
        # ordre kill-chain (par position canonique, fallback temps)
        stages.sort(key=lambda s: (ORD.get(s["tactic"], 99), s["first"]))
        firsts = [s["first"] for s in stages]
        out.append({"entity": ent, "raw": raw, "stages": stages,
                    "first": min(firsts), "last": max(s["first"] for s in stages)})
    return out

def main():
    now = datetime.now(timezone.utc)
    nowts = now.timestamp()
    state = load_state()
    n = 0; skipped = 0
    for etype, efield in (("host", "host"), ("user", "user")):
        for inc in correlate(efield):
            ent = inc["entity"]
            if etype == "user" and (not ent or ent.endswith("$")):
                continue
            score = saturate(inc["raw"])
            stages = inc["stages"]
            # dedup : meme entite + meme jeu de tactiques signale recemment -> on saute
            sig = "|".join(sorted({s["tactic"] for s in stages}))
            key = f"{etype}:{ent}"
            prev = state.get(key)
            if prev and prev.get("sig") == sig and (nowts - prev.get("ts", 0)) < REEMIT_H * 3600:
                skipped += 1
                continue
            chain = " -> ".join(f"{s['tactic']}({s['tech']})" for s in stages)
            try:
                span = (datetime.fromisoformat(inc["last"].replace("Z", "+00:00"))
                        - datetime.fromisoformat(inc["first"].replace("Z", "+00:00"))).total_seconds() / 3600.0
            except Exception:
                span = 0
            n += 1
            gelf({"event_source": "incident", "entity_type": etype, "incident_entity": ent,
                  "incident_score": score, "incident_severity": severity(score),
                  "incident_tactics": len(stages),
                  "incident_tactic_list": ", ".join(s["tactic"] for s in stages),
                  "incident_techniques": ", ".join(sorted({t for s in stages for t in s["tech"].split(",") if t})),
                  "incident_kill_chain": chain,
                  "incident_first_seen": inc["first"], "incident_last_seen": inc["last"],
                  "incident_span_h": round(span, 1),
                  "short_message": f"INCIDENT {etype} {ent} [{severity(score)} {score}/100] {len(stages)} tactiques : {chain}"})
            state[key] = {"sig": sig, "ts": nowts, "score": score}
            print(f"  [{severity(score)} {score}] {etype} {ent}: {chain}")
    # borne le fichier d'etat : on oublie les cles plus vieilles que 2x la fenetre
    cutoff = nowts - 2 * WINDOW_H * 3600
    state = {k: v for k, v in state.items() if v.get("ts", 0) >= cutoff}
    save_state(state)
    print(f"[incident] emis={n} ignores_dedup={skipped} (fenetre {WINDOW_H}h, reemit {REEMIT_H}h, min {MIN_TACTICS} tactiques)")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-incident-correlate KO:", e, file=sys.stderr); sys.exit(1)
NDREOF
chmod 755 /usr/local/sbin/omni-incident-correlate
require_api

echo "==> [1/2] Routage event_source=incident -> 'OMNI - Interne SIEM' (+ exclusion M365)"
ST="$(get_stream_id 'OMNI - Interne SIEM')"
[[ -n "${ST}" ]] || die "stream interne introuvable (lancer 21)."
CUR="$(api_get "/streams/${ST}" | jq -r '.rules[]? | select(.field=="event_source") | .value')"
if echo "${CUR}" | grep -qx "incident"; then skip "regle event_source=incident deja presente"
else
  jq -n '{field:"event_source", type:1, value:"incident", inverted:false, description:"correlation attack-chain"}' \
    | api_post "/streams/${ST}/rules" >/dev/null && ok "regle event_source=incident ajoutee"
fi
M365="$(get_stream_id 'OMNI - M365')"
if [[ -n "${M365}" ]]; then
  MEX="$(api_get "/streams/${M365}" | jq -r '.rules[]? | select(.field=="event_source" and .inverted==true) | .value')"
  if echo "${MEX}" | grep -qx "incident"; then skip "M365 exclut deja incident"
  else
    jq -n '{field:"event_source", type:1, value:"incident", inverted:true, description:"exclusion incident (anti-dup)"}' \
      | api_post "/streams/${M365}/rules" >/dev/null && ok "M365 exclut desormais incident"
  fi
else warn "stream M365 introuvable (exclusion non posee)"; fi

echo "==> [2/2] Service + timer (15 min) + premier passage"
cat > /etc/systemd/system/omni-incident-correlate.service <<'EOF'
[Unit]
Description=OMNI SIEM - correlation attack-chain (incidents)
After=network-online.target graylog-server.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-incident-correlate
Nice=15
EOF
cat > /etc/systemd/system/omni-incident-correlate.timer <<'EOF'
[Unit]
Description=OMNI SIEM - correlation incidents (15 min)

[Timer]
OnBootSec=120
OnUnitActiveSec=900
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now omni-incident-correlate.timer >/dev/null 2>&1 || true
systemctl start omni-incident-correlate.service && ok "$(journalctl -u omni-incident-correlate.service -n 1 --no-pager -o cat 2>/dev/null)" || warn "1er passage KO"

echo
echo "=== 44-incidents.sh termine. Relancer 14 (page Incidents) + 13 (alerte). ==="
