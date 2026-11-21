# ESXi / vCenter -> Graylog — procédure

Côté SIEM tout est prêt (script `19-vsphere.sh` exécuté) : inputs syslog
**TCP+UDP 1516** dédiés vSphere, index `omni-vsphere` (90 j), stream
`OMNI - vSphere`, pipeline de parsing/détection (extraction user/IP, tags
auth_fail / shell_ssh / vm_destroy / config), 3 alertes (mail+Teams) et la page
dashboard **vSphere**. Pare-feu : 1516 ouvert pour `VSPHERE_NET` (10.33.0.0/16,
à restreindre au VLAN management dans `00-vars.env`).

Cible : `10.33.220.10` port `1516` (TCP recommandé, UDP accepté).

## 1. ESXi (par hôte) — via SSH ou esxcli

```sh
# Destination syslog (TCP ; "udp://" possible)
esxcli system syslog config set --loghost='tcp://10.33.220.10:1516'
esxcli system syslog reload

# Ouvrir le flux sortant syslog dans le pare-feu ESXi
esxcli network firewall ruleset set --ruleset-id=syslog --enabled=true
esxcli network firewall refresh
```
Ou en GUI : **Host > Configure > System > Advanced System Settings >
`Syslog.global.logHost`** = `tcp://10.33.220.10:1516`.
Déploiement de masse : **Host Profiles** ou PowerCLI
`Set-VMHostSysLogServer -SysLogServer 'tcp://10.33.220.10:1516' -VMHost $esx`.

## 2. vCenter Server Appliance (VCSA)

GUI : **Administration > System Configuration > (node) > Syslog** (ou, selon
version, **VAMI** `https://<vcsa>:5480 > Syslog`) :
- Server `10.33.220.10`, Port `1516`, Protocole `TCP`.
- Jusqu'à 3 destinations possibles ; ajouter celle-ci.

## 3. Vérification (sur le SIEM, ~2 min après)

```bash
# paquets recus ?
timeout 10 tcpdump -ni any port 1516 -c 5
# events parses ?
curl -s "127.0.0.1:9200/omni-vsphere_*/_search?size=5" -H 'Content-Type: application/json' \
  -d '{"sort":[{"timestamp":"desc"}]}' \
  | jq -r '.hits.hits[]._source | "\(.host) | \(.event_action // "-") | \(.user // "-") | \(.alert_tag // "-")"'
```
Puis dashboard **OMNI - SOC > vSphere**.

## 4. Affinage (après réception des vrais logs)

Le parsing est volontairement large (basé sur le texte syslog). Une fois de
vrais logs ESXi/VCSA reçus, on affinera les regex d'extraction (user/IP) et les
motifs de détection selon ta version exacte (ESXi 7/8, VCSA). Détections
candidates à ajouter ensuite : modification de permissions vCenter, sortie du
lockdown mode, montage de datastore, snapshots massifs (ransomware), création
de comptes locaux ESXi.

## 5. Bon à savoir
- ESXi est verbeux : le volume peut être notable. L'index `omni-vsphere` est en
  rotation quotidienne, rétention 90 j (ajustable dans `19-vsphere.sh`).
- Garde au moins 1 hôte en TCP (fiable) ; l'UDP peut perdre des messages sous
  charge.
- Les events de test injectés pour valider le pipeline sont visibles dans
  l'index (host `esxi01`/`vcenter`) ; ils disparaîtront avec la rotation.
