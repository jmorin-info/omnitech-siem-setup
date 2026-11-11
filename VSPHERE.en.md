# ESXi / vCenter -> Graylog — procedure

On the SIEM side everything is ready (script `19-vsphere.sh` executed): dedicated
vSphere syslog inputs **TCP+UDP 1516**, index `omni-vsphere` (90 d), stream
`OMNI - vSphere`, a parsing/detection pipeline (user/IP extraction, tags
auth_fail / shell_ssh / vm_destroy / config), 3 alerts (e-mail+Teams) and the
**vSphere** dashboard page. Firewall: 1516 open for `VSPHERE_NET` (10.33.0.0/16,
to be restricted to the management VLAN in `00-vars.env`).

Target: `10.33.220.10` port `1516` (TCP recommended, UDP accepted).

## 1. ESXi (per host) — via SSH or esxcli

```sh
# Syslog destination (TCP ; "udp://" also possible)
esxcli system syslog config set --loghost='tcp://10.33.220.10:1516'
esxcli system syslog reload

# Open the outbound syslog flow in the ESXi firewall
esxcli network firewall ruleset set --ruleset-id=syslog --enabled=true
esxcli network firewall refresh
```
Or via GUI: **Host > Configure > System > Advanced System Settings >
`Syslog.global.logHost`** = `tcp://10.33.220.10:1516`.
Mass deployment: **Host Profiles** or PowerCLI
`Set-VMHostSysLogServer -SysLogServer 'tcp://10.33.220.10:1516' -VMHost $esx`.

## 2. vCenter Server Appliance (VCSA)

GUI: **Administration > System Configuration > (node) > Syslog** (or, depending
on version, **VAMI** `https://<vcsa>:5480 > Syslog`):
- Server `10.33.220.10`, Port `1516`, Protocol `TCP`.
- Up to 3 destinations possible; add this one.

## 3. Verification (on the SIEM, ~2 min later)

```bash
# packets received?
timeout 10 tcpdump -ni any port 1516 -c 5
# events parsed?
curl -s "127.0.0.1:9200/omni-vsphere_*/_search?size=5" -H 'Content-Type: application/json' \
  -d '{"sort":[{"timestamp":"desc"}]}' \
  | jq -r '.hits.hits[]._source | "\(.host) | \(.event_action // "-") | \(.user // "-") | \(.alert_tag // "-")"'
```
Then the **OMNI - SOC > vSphere** dashboard.

## 4. Tuning (after receiving real logs)

Parsing is deliberately broad (based on the syslog text). Once real ESXi/VCSA
logs are received, we will refine the extraction regexes (user/IP) and the
detection patterns for your exact version (ESXi 7/8, VCSA). Detections to add
next: vCenter permission changes, exit from lockdown mode, datastore mount,
mass snapshots (ransomware), ESXi local-account creation.

## 5. Good to know
- ESXi is verbose: the volume can be significant. The `omni-vsphere` index rotates
  daily, 90 d retention (adjustable in `19-vsphere.sh`).
- Keep at least one host on TCP (reliable); UDP can drop messages under load.
- The test events injected to validate the pipeline are visible in the index
  (host `esxi01`/`vcenter`); they will disappear with rotation.
