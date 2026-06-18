# FortiAnalyzer → Graylog — procédure complète

Objectif : le FAZ (10.33.80.253) forwarde les logs FortiGate vers Graylog
(10.33.220.10:1514). Côté Graylog **tout est déjà prêt et vérifié** :
inputs syslog TCP+UDP 1514 RUNNING, pare-feu nftables ouvert pour
10.33.80.253 uniquement, pipeline `OMNI - FortiGate` (parsing key=value,
`srcip→src_ip`, GeoIP, tag `alert_tag:fortigate_utm`), stream + index
`omni-fortigate` (90 j), dashboard `OMNI - FortiGate`, alerte
`OMNI - FortiGate : virus / IPS`.

## 1. Configuration côté FAZ (GUI)

*System Settings > Advanced > Log Forwarding > Create New* :

| Champ | Valeur |
|---|---|
| Status | Enabled |
| Remote Server Type | **Syslog** |
| Server FQDN/IP | `10.33.220.10` |
| Port | `1514` |
| Reliable Connection | **ON** (= TCP ; OFF = UDP, accepté aussi mais sans garantie) |
| Sending Frequency | Real-time |
| Log Forwarding Filters | voir ci-dessous |

**Filtres recommandés** (le FAZ reste le lac réseau exhaustif ; on n'envoie à
Graylog que ce qui sert à la corrélation — sinon le trafic `accept` noie tout) :
- Device : le(s) FortiGate
- Log filters (OR) :
  - `level` ≥ `warning`
  - `subtype` = `vpn` (toutes connexions SSL-VPN / IPsec)
  - `subtype` = `admin` ou `system` (actions d'admin sur le FW)
  - `logid` des échecs d'authentification (event/user)
  - UTM : `virus`, `ips`, `webfilter` (blocages), `application`
- Exclure : `type=traffic action=accept` (volumétrie sans valeur SIEM).

## 2. Équivalent CLI FAZ

```
config system log-forward
  edit 1
    set mode forwarding
    set fwd-server-type syslog
    set server-addr 10.33.220.10
    set server-port 1514
    set fwd-reliable enable
    set fwd-max-delay realtime
    set log-filter-status enable
    set log-filter-logic or
    config log-filter
      edit 1
        set field level
        set oper >=
        set value warning
      next
      edit 2
        set field subtype
        set oper =
        set value vpn
      next
    end
  next
end
```

## 3. Vérification (sur la VM Graylog)

```bash
cd ~/omnitech-siem-setup && source 00-vars.env && source lib-graylog.sh
# 1. Paquets qui arrivent ?
tcpdump -ni any host 10.33.80.253 and port 1514 -c 5
# 2. Input qui compte ?
api_get /system/metrics/namespace/org.graylog2.inputs | \
  jq -r '.metrics[] | select(.full_name|test("Syslog.*incomingMessages")) | "\(.full_name): \(.metric.count)"'
# 3. Messages parses ? (event_source pose par le pipeline)
curl -s "127.0.0.1:9200/omni-fortigate_*/_search?size=3" \
  -H 'Content-Type: application/json' -d '{"sort":[{"timestamp":"desc"}]}' | \
  jq '.hits.hits[]._source | {timestamp, host, src_ip, dest_ip, action, app, alert_tag}'
```
Puis console : dashboard **OMNI - FortiGate** doit se peupler.

## 4. Notes

- Le pipeline se déclenche sur la présence de `devname=` dans le message :
  format syslog FortiGate/FAZ natif (key=value), aucun extracteur à créer.
- Si vous préférez le format **CEF** côté FAZ : créer l'input *CEF TCP* port
  5555 dans Graylog (System > Inputs), ouvrir 5555/tcp dans
  `06-firewall.sh` pour 10.33.80.253, et adapter le routage du stream
  `OMNI - FortiGate` (ajouter une règle sur l'input CEF). Le syslog 1514
  reste le chemin le plus simple et déjà testé.
- Horodatage : en production le FAZ met l'heure réelle dans l'en-tête syslog ;
  les messages apparaissent immédiatement dans les recherches relatives
  (le test manuel d'aujourd'hui semblait « invisible » uniquement parce que
  son timestamp artisanal était dans le futur).

---

# REVISION (11/06) — il manque toute la telemetrie UTM

## Constat (mesure sur 2 h de flux reel)
- traffic : 1 013 419 (95 %)  | event : 52 976 | **utm : 1 465 (uniquement `voip`)**
- **Aucun virus / ips / webfilter / dns / app-ctrl** ne remonte.

=> Ce n'est PAS le FAZ ni Graylog : le **FortiGate ne logge pas ses profils de
securite**. Sans ca, le SIEM est aveugle sur les menaces reseau (malware bloque,
intrusions IPS, C2 via DNS, navigation interdite). C'est le trou le plus grave.

## 1. Cote FortiGate — activer le logging UTM (le vrai correctif)
Sur CHAQUE policy sortante qui doit etre inspectee :
```
config firewall policy
  edit <id>
    set utm-status enable
    set av-profile "default"
    set ips-sensor "default"
    set webfilter-profile "default"
    set dnsfilter-profile "default"
    set application-list "default"
    set ssl-ssh-profile "certificate-inspection"
    set logtraffic all
  next
end
```
Puis s'assurer que chaque profil ECRIT des logs :
```
config antivirus profile
  edit "default"
    set av-virus-log enable
    set av-block-log enable
  next
end
config webfilter profile
  edit "default"
    set extended-log enable
    config ftgd-wf
      set options error-allow rate-server-ip
    end
  next
end
config application list
  edit "default"
    set extended-log enable
    set other-application-log enable
    set unknown-application-log enable
  next
end
config dnsfilter profile
  edit "default"
    set log-all-domain enable
  next
end
```
(IPS : les signatures loggent par defaut ; verifier `config ips sensor` -> action
log enable sur les filtres.)

## 2. Cote FAZ — filtre de forwarding revise (garder tout le pertinent)
Logique OR : on garde event (vpn/user/admin/system), utm (toutes signatures),
anomaly (DoS), trafic bloque, et tout ce qui est >= warning. Seul le trafic
`accept`/`notice` verbeux est jete.
```
config system log-forward
  edit 1
    set log-filter-status enable
    set log-filter-logic or
    config log-filter
      edit 1
        set field type
        set oper =
        set value event
      next
      edit 2
        set field type
        set oper =
        set value utm
      next
      edit 3
        set field type
        set oper =
        set value anomaly
      next
      edit 4
        set field action
        set oper =
        set value deny
      next
      edit 5
        set field level
        set oper >=
        set value warning
      next
    end
  next
end
```
Option : ajouter `subtype = local` (trafic local-in/out vers le FortiGate =
acces admin) si tu veux tracer l'administration du firewall.

## 3. Verification (sur le SIEM, ~5 min apres)
```bash
curl -s "127.0.0.1:9200/omni-fortigate_*/_search?size=0" -H 'Content-Type: application/json' \
 -d '{"query":{"bool":{"must":[{"term":{"type":"utm"}},{"range":{"timestamp":{"gte":"now-15m"}}}]}},
      "aggs":{"x":{"terms":{"field":"subtype","size":15}}}}' | jq -r '.aggregations.x.buckets[]|"\(.doc_count)\t\(.key)"'
```
Tu dois voir apparaitre virus / ips / webfilter / dns / app-ctrl. Le dashboard
page "Reseau" se peuplera alors en detections UTM reelles.
