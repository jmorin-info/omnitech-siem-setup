"""Découverte réseau / scan de ports OMS-XDR.

Reproduit la fonction « Network Attack Defense / asset discovery » :
- scan nmap du périmètre interne déclaré
- comparaison à une baseline (delta = nouveau port ouvert / hôte / service)
- chaque delta est réinjecté dans Graylog (GELF) -> consommé par la corrélation

Usage :
    python -m oms_xdr.netscan --mode quick   # top-1000 (cadence horaire)
    python -m oms_xdr.netscan --mode full    # -p- (hebdomadaire)
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .config import load_config
from .graylog_client import GraylogClient

log = logging.getLogger("oms-xdr.netscan")


def _build_nmap_cmd(cfg: dict, mode: str) -> list[str]:
    nc = cfg["netscan"]
    cmd = [nc.get("binary", "nmap"), "-sS", "-Pn", "-n", "--open", "-oX", "-"]
    cmd += ["--min-rate", str(nc.get("rate_pps", 500))]
    if mode == "full":
        cmd += ["-p-"]
    else:
        cmd += ["--top-ports", "1000"]
    for ex in nc.get("exclude", []):
        cmd += ["--exclude", ex]
    cmd += list(nc.get("targets", []))
    return cmd


def run_scan(cfg: dict, mode: str) -> dict[str, dict[int, str]]:
    """Retourne {ip: {port: service}} pour les ports ouverts."""
    cmd = _build_nmap_cmd(cfg, mode)
    log.info("nmap: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    except FileNotFoundError:
        log.error("nmap introuvable — installer 'nmap' (apt install nmap).")
        return {}
    except subprocess.TimeoutExpired:
        log.error("Scan interrompu (timeout).")
        return {}
    if proc.returncode != 0 and not proc.stdout:
        log.error("nmap a échoué: %s", proc.stderr.strip())
        return {}
    return _parse_nmap_xml(proc.stdout)


def _parse_nmap_xml(xml_text: str) -> dict[str, dict[int, str]]:
    result: dict[str, dict[int, str]] = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        log.error("XML nmap illisible: %s", exc)
        return result
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        ports: dict[int, str] = {}
        for p in host.findall("./ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(p.get("portid", "0"))
            svc_el = p.find("service")
            svc = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            ports[portid] = svc
        if ports:
            result[ip] = ports
    return result


def _load_baseline(path: str) -> dict[str, dict[str, str]]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return {}


def _save_baseline(path: str, scan: dict[str, dict[int, str]]) -> None:
    serial = {ip: {str(pt): svc for pt, svc in ports.items()} for ip, ports in scan.items()}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(serial, indent=2))


def diff_and_report(cfg: dict, scan: dict[str, dict[int, str]],
                    gl: GraylogClient) -> list[dict[str, Any]]:
    """Compare le scan à la baseline, émet les deltas vers Graylog."""
    baseline = _load_baseline(cfg["netscan"]["baseline_file"])
    findings: list[dict[str, Any]] = []

    for ip, ports in scan.items():
        known = baseline.get(ip, {})
        if not known:
            findings.append(_finding("new_host", ip, None,
                                     f"Nouvel hôte actif {ip} ({len(ports)} ports ouverts)"))
        for port, svc in ports.items():
            if str(port) not in known:
                findings.append(_finding("new_open_port", ip, port,
                                         f"Nouveau port ouvert {ip}:{port}/{svc}"))
    # ports fermés (information de durcissement)
    for ip, known in baseline.items():
        cur = scan.get(ip, {})
        for port in known:
            if int(port) not in cur:
                findings.append(_finding("closed_port", ip, int(port),
                                         f"Port désormais fermé {ip}:{port}"))

    for f in findings:
        # GELF : seuls version/host/short_message/full_message/timestamp/level sont
        # des clés réservées ; tout champ additionnel DOIT être préfixé '_'.
        gl.send_gelf({
            "host": f["target_host"],
            "short_message": f["message"],
            "_event_source": "oms_netscan",
            "_oms_event": f["oms_event"],
            "_target_host": f["target_host"],
            "_target_port": f.get("target_port"),
            "_source_module": "oms-netscan",
            "level": 4 if f["oms_event"] != "closed_port" else 6,
        })

    _save_baseline(cfg["netscan"]["baseline_file"], scan)
    log.info("Scan terminé : %d hôtes, %d deltas signalés.", len(scan), len(findings))
    return findings


def _finding(event: str, ip: str, port: int | None, msg: str) -> dict[str, Any]:
    return {"oms_event": event, "target_host": ip, "target_port": port, "message": msg}


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    ap = argparse.ArgumentParser(description="OMS-XDR — découverte réseau")
    ap.add_argument("--mode", choices=["quick", "full"], default="quick")
    ap.add_argument("--config", default="/etc/oms-xdr/config.yaml")
    args = ap.parse_args()

    cfg = load_config(args.config)
    if not cfg["netscan"].get("enabled", True):
        log.info("netscan désactivé dans la configuration.")
        return
    gl = GraylogClient(cfg["graylog"])
    scan = run_scan(cfg, args.mode)
    diff_and_report(cfg, scan, gl)


if __name__ == "__main__":
    main()
