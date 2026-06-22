#!/usr/bin/env bash
# =============================================================================
# 61-supervision-robots.sh - Versionne les robots de supervision (IaC / PRA).
#   omni-self-health    : auto-supervision des robots (le filet "qui surveille
#                         les surveillants") -> GELF event_source=siem_health.
#   omni-collect-health : supervision de la COLLECTE (couverture SLA + go-dark)
#                         -> GELF event_source=collecte_sla.
#   Ces deux binaires etaient deployes a la main et N'ETAIENT versionnes par
#   AUCUN script -> une reconstruction PRA les perdait (39/46 faisaient 'die').
#   Ce script les (re)installe a l'identique. A lancer AVANT 39 et 46.
# Idempotent. Sans prerequis API.
# =============================================================================
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }

echo "==> [1/3] omni-self-health"
cat > /usr/local/sbin/omni-self-health <<'PYEOF'
#!/usr/bin/env python3
# =============================================================================
# omni-self-health - Auto-supervision des robots d'analyse du SIEM.
#   Verifie que chaque collecteur (UEBA/NDR/incidents/collecte/vuln/carte) a bien
#   TOURNE et REUSSI recemment (etat systemd). Si un job a echoue ou ne tourne plus
#   (timer mort), la detection s'arrete EN SILENCE -> on emet une alerte. C'est le
#   filet de securite "qui surveille les surveillants".
#   Emet GELF event_source=siem_health : 1 synthese + 1 par job en panne
#   (alert_tag=siem_job_fail).
# Lance par timer (toutes les 30 min). Sans config.
# =============================================================================
import json, os, subprocess, sys, urllib.request

GELF_URL = "http://127.0.0.1:12201/gelf"
SIEM = "bx-it-graylog-vm"

# unit : age max tolere (s) = ~3x la cadence du timer (rate un cycle = OK, deux = alerte)
JOBS = {
    "omni-collect-health":     7200,
    "omni-vuln-scan":        180000,
    "omni-ueba-volume":        7200,
    "omni-ueba-geo":           4500,
    "omni-ndr-beacon":        43200,
    "omni-ndr-dns":            7200,
    "omni-ueba-score":         4500,
    "omni-incident-correlate": 2400,
    "omni-ndr-scan":           2400,
    "omni-ndr-exfil":          7200,
    "omni-ueba-geo-newcountry": 14400,
    "omni-ldap-recon":         2400,
    "omni-ndr-lateral":        3600,
    "omni-geo-flux":            300,
    "omni-fortidhcp-fetch":    2700,
    "omni-m365-fetch":         1800,
    "omni-m365-activity":      3600,
    "omni-integrity":        172800,
}

def gelf(fields):
    if os.environ.get("UEBA_DRY"):
        return
    base = {"version": "1.1", "host": SIEM, "short_message": fields.get("short_message", "siem_health")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def uptime():
    return float(open("/proc/uptime").read().split()[0])

def show(unit):
    p = subprocess.run(["systemctl", "show", unit + ".service",
                        "-p", "LoadState", "-p", "Result", "-p", "ExecMainStatus",
                        "-p", "ActiveState",
                        "-p", "ExecMainExitTimestampMonotonic",
                        "-p", "InactiveEnterTimestampMonotonic"],
                       capture_output=True, text=True, timeout=10)
    d = {}
    for line in p.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1); d[k] = v
    return d

def main():
    up = uptime()
    ok_n, bad, maint = 0, [], []   # bad = PANNES réelles (robots/infra) ; maint = rappels maintenance (reboot)
    for unit, maxage in JOBS.items():
        d = show(unit)
        load = d.get("LoadState", "")
        result = d.get("Result", "")
        # On prend le PLUS RECENT de 2 horodatages monotones : ExecMainExit (fin du
        # main process) ET InactiveEnter (passage inactif = fin de run). Robuste aux
        # oneshots rapides (geo-flux/30s) captes a chaud et aux daemon-reload qui
        # remettent ExecMainExit a 0 -> evite les FAUX "robot en panne".
        def _us(k):
            try: return int(d.get(k, "0") or 0)
            except ValueError: return 0
        last_us = max(_us("ExecMainExitTimestampMonotonic"), _us("InactiveEnterTimestampMonotonic"))
        active = d.get("ActiveState", "")
        if last_us:
            age = up - last_us / 1e6
        elif active in ("active", "activating", "reloading"):
            age = 0          # en cours d'execution -> sain (pas encore d'horodatage de fin)
        else:
            age = up         # jamais execute depuis le boot -> grace = uptime
        reason = None
        if load != "loaded":
            reason = f"unite absente ({load})"
        elif result not in ("success",):
            reason = f"dernier resultat={result}"
        elif age > maxage:
            reason = f"pas execute depuis {int(age/60)} min (max {int(maxage/60)})"
        if reason:
            bad.append((unit, reason, int(age)))
            gelf({"event_source": "siem_health", "health_type": "job_fail",
                  "alert_tag": "siem_job_fail", "health_job": unit, "health_reason": reason,
                  "health_age_s": int(age),
                  "short_message": f"ROBOT SIEM EN PANNE : {unit} - {reason}"})
            print(f"  [PANNE] {unit}: {reason}")
        else:
            ok_n += 1

    # Infra : volume /data (chiffre LUKS) bien ouvert + monte ? Nouvelle surface
    # depuis le chiffrement au repos -> si le TPM echoue au boot ou si /data est
    # demonte, la collecte s'arrete. Signale via le meme canal que les robots.
    infra = []
    if not os.path.ismount("/data"):
        infra.append("/data NON monte")
    if not os.path.exists("/dev/mapper/cryptdata"):
        infra.append("mapper LUKS 'cryptdata' absent (volume non dechiffre)")
    if infra:
        msg = "; ".join(infra)
        bad.append(("stockage-chiffre", msg, 0))
        gelf({"event_source": "siem_health", "health_type": "infra_fail",
              "alert_tag": "siem_job_fail", "health_job": "stockage-chiffre",
              "health_reason": msg,
              "short_message": f"STOCKAGE SIEM DEGRADE : {msg}"})
        print(f"  [INFRA] {msg}")

    # MAJ securite : reboot en attente (noyau/lib patche non encore actif) = vulnerabilite
    # si oublie. Reboot du SIEM = MANUEL en fenetre (/data chiffre LUKS2/TPM2). On signale.
    reboot_req = os.path.exists("/var/run/reboot-required") or os.path.exists("/run/reboot-required")
    if not reboot_req:
        try:
            r = subprocess.run(["needrestart", "-b", "-k"], capture_output=True, text=True, timeout=30)
            for ln in r.stdout.splitlines():
                if ln.startswith("NEEDRESTART-KSTA:") and int(ln.split(":")[1]) >= 3:
                    reboot_req = True
        except Exception:
            pass
    if reboot_req:
        # Reboot = RAPPEL DE MAINTENANCE, PAS une panne de robot (sinon faux "1 en panne").
        maint.append("reboot requis (MAJ securite)")
        gelf({"event_source": "siem_health", "health_type": "reboot_required",
              "alert_tag": "siem_maintenance", "health_job": "maj-securite",
              "health_reason": "reboot requis apres MAJ securite - planifier en fenetre + valider TPM",
              "short_message": "MAJ SECURITE : reboot du SIEM requis (fenetre + valider le TPM)"})
        print("  [PATCH] reboot requis (MAJ securite)")

    # Synthese : on distingue les PANNES (robots/infra = action immediate) des
    # RAPPELS de maintenance (reboot planifie) -> plus de faux "robot en panne".
    note = ""
    if bad:
        note += f", {len(bad)} en panne"
    if maint:
        note += f" · {len(maint)} maintenance (reboot securite)"
    gelf({"event_source": "siem_health", "health_type": "summary",
          "health_ok": ok_n, "health_fail": len(bad), "health_total": len(JOBS),
          "health_maint": len(maint),
          "short_message": f"Auto-supervision SIEM : {ok_n}/{len(JOBS)} robots OK{note}"})
    print(f"[self-health] {ok_n}/{len(JOBS)} robots OK{note}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-self-health KO:", e, file=sys.stderr); sys.exit(1)
PYEOF
chmod 755 /usr/local/sbin/omni-self-health && echo "    [+] /usr/local/sbin/omni-self-health (755)"

echo "==> [2/3] omni-collect-health"
cat > /usr/local/sbin/omni-collect-health <<'PYEOF'
#!/usr/bin/env python3
# =============================================================================
# omni-collect-health - Supervision de la COLLECTE (couverture SLA + go-dark).
#   Sans CMDB : le parc "gere" est derive du baseline -> tout hote ayant emis
#   recemment (< COLLECT_MANAGED_DAYS) est cense continuer a emettre.
#     - last_seen par hote (max timestamp) sur la fenetre baseline ;
#     - go-dark = hote gere silencieux depuis > COLLECT_GO_DARK_HOURS ;
#     - couverture = hotes actifs 24h / hotes geres * 100.
#   Resultats en GELF (event_source=collecte_sla) -> page Sante collecte + alerte.
#   Le host cible (reserve GELF) part en champ custom 'dark_host'.
# Lance par omni-collect-health.timer (horaire). Config dans 00-vars.env.
# =============================================================================
import json, os, re, sys, urllib.request
from datetime import datetime, timezone

OS_URL   = "http://127.0.0.1:9200"
GELF_URL = "http://127.0.0.1:12201/gelf"
SIEM     = "bx-it-graylog-vm"
# Indices des sources a AGENT (hotes physiques). On EXCLUT M365 (cloud, pas d'hote)
# et l'interne SIEM (auto-genere). FortiGate/vSphere = equipements, mais leur
# "host" = nom d'equipement : legitime a superviser aussi.
IDX = "omni-winsec*,omni-sysmon*,omni-winother*,omni-fortigate*,omni-vsphere*"

def load_env(path="/root/omnitech-siem-setup/00-vars.env"):
    env = {}
    try:
        for line in open(path):
            m = re.match(r"\s*([A-Z_]+)=(.*)", line)
            if m: env[m.group(1)] = m.group(2).strip().strip("'").strip('"')
    except OSError: pass
    return env
ENV = load_env()
GO_DARK_HOURS = float(ENV.get("COLLECT_GO_DARK_HOURS", "26"))   # tolere une nuit + marge
MANAGED_DAYS  = int(ENV.get("COLLECT_MANAGED_DAYS", "14"))      # au-dela = decommissionne
BASELINE_DAYS = max(MANAGED_DAYS, 30)

def es(path, body):
    req = urllib.request.Request(OS_URL + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def gelf(fields):
    # GELF 'host' reserve = emetteur (-> 'source'). Les champs custom sont prefixes '_'.
    base = {"version": "1.1", "host": SIEM, "short_message": fields.get("short_message", "collecte_sla")}
    base.update({("_" + k if not k.startswith(("_", "version", "short_message")) else k): v
                 for k, v in fields.items()})
    try:
        urllib.request.urlopen(urllib.request.Request(GELF_URL, data=json.dumps(base).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception as e:
        print("gelf KO:", e, file=sys.stderr)

def main():
    now = datetime.now(timezone.utc)
    # last_seen + volume par hote sur la fenetre baseline
    agg = es(f"/{IDX}/_search", {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": f"now-{BASELINE_DAYS}d"}}},
        "aggs": {"h": {"terms": {"field": "host", "size": 5000},
                       "aggs": {"last": {"max": {"field": "timestamp"}},
                                "first": {"min": {"field": "timestamp"}}}}}})
    buckets = agg["aggregations"]["h"]["buckets"]

    managed = active24 = go_dark = decommissioned = 0
    dark_hosts = []
    for b in buckets:
        host = b["key"]
        last_ms = b["last"]["value"]
        if last_ms is None:
            continue
        last = datetime.fromtimestamp(last_ms / 1000.0, tz=timezone.utc)
        hours_silent = (now - last).total_seconds() / 3600.0
        days_silent = hours_silent / 24.0
        if days_silent > MANAGED_DAYS:
            decommissioned += 1
            continue                          # hors SLA (probablement retire)
        managed += 1
        if hours_silent <= 24:
            active24 += 1
        if hours_silent > GO_DARK_HOURS:
            go_dark += 1
            first = datetime.fromtimestamp(b["first"]["value"] / 1000.0, tz=timezone.utc)
            dark_hosts.append((host, last, round(hours_silent, 1), b["doc_count"], first))

    coverage = round(active24 / managed * 100.0, 1) if managed else 0.0

    # 1) evenement de synthese (le KPI couverture lit sla_coverage_pct)
    gelf({"event_source": "collecte_sla", "sla_type": "summary",
          "sla_expected": managed, "sla_active_24h": active24,
          "sla_go_dark": go_dark, "sla_decommissioned": decommissioned,
          "sla_coverage_pct": coverage,
          "short_message": f"Couverture collecte {coverage}% - {active24}/{managed} actifs, {go_dark} go-dark"})

    # 2) un evenement par hote go-dark (alert_tag pour coloration + alerte)
    for host, last, hrs, vol, first in sorted(dark_hosts, key=lambda x: -x[2]):
        gelf({"event_source": "collecte_sla", "sla_type": "go_dark",
              "alert_tag": "host_go_dark", "dark_host": host,
              "last_seen": last.strftime("%Y-%m-%d %H:%M:%S UTC"),
              "hours_silent": hrs, "host_volume_30d": vol,
              "first_seen": first.strftime("%Y-%m-%d %H:%M:%S UTC"),
              "short_message": f"GO-DARK {host} - muet depuis {hrs}h (dernier log {last.strftime('%d/%m %H:%M')})"})

    print(f"[collecte] geres={managed} actifs24h={active24} go-dark={go_dark} "
          f"decommissionnes={decommissioned} couverture={coverage}%")
    if dark_hosts:
        print("  go-dark:", ", ".join(f"{h}({hrs}h)" for h, _, hrs, _, _ in dark_hosts))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("omni-collect-health KO:", e, file=sys.stderr)
        sys.exit(1)
PYEOF
chmod 755 /usr/local/sbin/omni-collect-health && echo "    [+] /usr/local/sbin/omni-collect-health (755)"

echo "==> [3/3] Verification syntaxe Python"
python3 -m py_compile /usr/local/sbin/omni-self-health /usr/local/sbin/omni-collect-health \
  && echo "    [+] les 2 robots compilent" || echo "    [!] erreur de compilation"

echo
echo "=== 61 termine. Robots de supervision versionnes (reconstructibles par le PRA)."
echo "    Lancer ensuite 39-collect-health.sh et 46-self-health.sh (timers)."
