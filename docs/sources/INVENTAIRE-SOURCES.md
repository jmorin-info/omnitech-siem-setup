# Inventaire des sources surveillées — SIEM OMNITECH

> Registre des sources de journaux collectées par le SIEM, leur volume,
> rétention et criticité. Alimente l'inventaire des actifs (ISO 27001 A.5.9) et
> prouve la couverture de surveillance (A.8.16). Le débit est mesuré
> automatiquement (voir page « Santé collecte » et supervision de couverture).

## 1. Sources collectées

| Source (stream) | Origine | Transport (input) | Volume ~/jour | Rétention | Criticité |
|-----------------|---------|-------------------|---------------|-----------|-----------|
| **Windows Security** | Postes & serveurs AD (audit) | Winlogbeat → Beats TLS 5044 | ~5,5 Go | **365 j** | Haute |
| **Sysmon** | Endpoints (télémétrie processus/réseau) | Winlogbeat → Beats TLS 5044 | ~1,8 Go* | **365 j** | Haute |
| **Windows autres** | Veeam (canal « Veeam Backup »), AD CS (PKI), Defender, services | Winlogbeat → Beats TLS 5044 | ~2,7 Go | **365 j** | Moyenne |
| **FortiGate** | Pare-feu (trafic, UTM, VPN) | FortiAnalyzer → syslog 1514 (key=value) | ~11 Go | **180 j** | Haute |
| **Microsoft 365 / Entra** | Cloud (sign-in, audit, activité) | API Graph → collecteur → GELF HTTP 12201 | ~0,02 Go | **365 j** | Haute |
| **vSphere** | ESXi / vCenter | syslog UDP/TCP 1516 | ~0,6 Go | **365 j** | Haute |
| **ESET PROTECT** | Console antivirus (10.33.50.20) | syslog JSON TCP 1515 (514 redirigé) | faible | **365 j** | Haute |
| **BunkerWeb (WAF)** | Reverse-proxy WAF (10.33.70.1) | Filebeat → Beats TLS 5044 | ~0,3 Go** | **90 j** | Haute |
| **Interne SIEM** | Analyses maison (UEBA/NDR/incidents/santé/vuln) | GELF local 12201 | faible | défaut | Haute |

\* Sysmon après filtrage du bruit (EventID 12 registre).
\*\* BunkerWeb après *drop* du bruit stderr/metrics (~97 % du volume brut).

**NPS (RADIUS, 10.33.50.247)** : déjà mappé côté SIEM (lookup `win-events.csv`,
EventID 6272/6273/6274 → `event_source:nps`). En attente de remontée : à
déployer Winlogbeat sur le serveur NPS. Alerte associée déjà créée (script 13).

Total ~22 Go/jour sur disque (avant compression). `/data` = 7,3 To dédié.
Détail capacité et projections : `POLITIQUE-RETENTION.md`.

## 2. Couverture & continuité (A.8.16)

- **Couverture mesurée** : taux d'hôtes « gérés » émettant dans les dernières
  24 h, calculé en continu (page « Santé collecte »). Cible : ~100 %.
- **Détection des trous** : un hôte qui cesse d'émettre (>26 h) est signalé
  *go-dark* (alerte P2) — couvre la panne d'agent comme le sabotage.
- **Auto-supervision** : les ~13 robots d'analyse sont eux-mêmes surveillés
  (alerte P3 si l'un s'arrête) — la détection ne peut pas devenir aveugle
  silencieusement.

## 3. Champs normalisés (interopérabilité)

Tous les événements sont normalisés vers un schéma commun (champs unifiés) pour
permettre la corrélation cross-source :

- Identité : `host`, `user`, `src_ip`, `src_host`, `event_id`, `event_action`,
  `event_source`, `event_category`.
- Sécurité : `alert_tag` (détection), `mitre_technique` / `mitre_tactic`,
  `risk_score` / `risk_severity`.
- Réseau : `action`, `dest_ip`, `dest_country`, `srccountry`, `bytes_*`,
  géolocalisation.
- M365 : `m365_type` (signin / audit / **risk** — Entra ID Protection), `m365_workload`,
  `src_country`, `upn` (`alert_tag:m365_risque` sur compte atRisk).
- ESET : `eset_event_type`, `eset_severity`, `eset_action`, `eset_target`, `eset_detail`,
  `eset_hostname`, `eset_user` (préfixe `eset_` ; `alert_tag:eset_detection` sur menace).
  *(Les champs `eset_threat_name`/`eset_object_uri` n'existent pas — corrigé 2026-06-14.)*
- BunkerWeb / WAF : `waf_vhost`, `http_method`, `http_url`, `http_status`,
  `http_user_agent`, `src_ip` (`alert_tag:waf_block` sur HTTP 403).
- Vaultwarden (coffre MDP) : `vault_user`, `src_ip`, `vw_level`, `vw_module`
  (routage `filebeat_event_source=vaultwarden`, index dédié `omni-vaultwarden`).
- Réseau/identité (enrichissement) : `src_hostname`/`dest_hostname` (attribution DHCP
  FortiGate, script 56), `identity`/`identity_human` (corrélation inter-sources, script 58).

Le routage de chaque source repose sur `event_source` (FortiGate, ESET, vSphere,
M365, Veeam, NPS) ou `filebeat_event_source` (BunkerWeb). Côté FortiGate, le
champ `source` Graylog est positionné sur le nom de l'équipement (`host` =
`devname` renommé), ce qui permet de séparer les logs par pare-feu.

## 4. Horodatage (A.8.17)

Toutes les sources et le SIEM sont synchronisés NTP sur le contrôleur de domaine
(PDC emulator, 10.33.50.250). Le champ `timestamp` est en UTC, cohérent entre
sources, ce qui garantit la fiabilité des corrélations temporelles (impossible
travel, kill-chain, beaconing).

Cas particulier FortiGate : l'horodatage SIEM est dérivé du champ `eventtime`
(epoch nanosecondes) émis par l'équipement, et non de l'en-tête syslog du FAZ —
ceci évite tout décalage lié au relais FortiAnalyzer.

## 5. Protection des sources (intégrité de la collecte)

- Flux entrants restreints par pare-feu local (nftables) aux sous-réseaux/hôtes
  autorisés (cf. `00-vars.env` : NET_BEATS, IP_FAZ, VSPHERE_NET, IP_ESET,
  IP_BUNKERWEB, IP_NPS).
- Transport chiffré pour les agents Beats (Winlogbeat / Filebeat) : entrée Beats
  TLS 5044 (certificat `/etc/graylog/certs/graylog.crt`). ESET, FortiGate et
  vSphere sont en syslog sur les VLAN internes restreints au pare-feu.
- Comptes de collecte dédiés (M365 : app Entra à privilèges de lecture ; AD :
  compte de service de bind LDAPS).

---
*Inventaire à tenir à jour lors de l'ajout/retrait d'une source. Voir
`ISO27001-MAPPING.md` (A.8.15/8.16), `INTEGRATION-SOURCES.md` (procédures
d'intégration) et `POLITIQUE-RETENTION.md` (durées). Revue : 2026-06-14.*
