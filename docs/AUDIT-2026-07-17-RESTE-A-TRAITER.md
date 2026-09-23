# Audit alerting/correlation du 17/07/2026 — reste a traiter

Ce document liste ce qui N'A PAS ete applique automatiquement, avec pour chaque item la
raison, le patch pret, et qui doit trancher. Les correctifs deja appliques (au depot, non
deployes) sont dans la synthese de session. Snapshot de rollback :
`/root/siem-snapshot-2026-07-17-avant-correctifs`.

## Regle de decision suivie
- Applique d'office : retouches d'affichage/produit du triage (meme fichier deja en attente
  de deploiement, risque nul), retrait d'emoji, motifs morts, bornage de score, champs de
  correlation, parking d'une detection inerte.
- NON applique : tout ce qui (a) ressuscite de la detection (rules.yaml : meme prudence que
  F.1/F.2 — un signal qui redevient vivant peut alimenter une correlation qui escalade),
  (b) exige une action via l'API Graylog (interdite en autonomie : GET seulement),
  (c) exige une donnee/decision de Julien.

---

## A. Signaux XDR morts — PATCH PRET, NE PAS livrer seul (rules.yaml)

Ces trois signaux referencent un champ d'entite qui n'existe pas -> 0 entite produite ->
jamais declenches. Les corriger les rend vivants. **Avant de livrer, verifier ce que chaque
signal alimente comme regle de correlation** (meme lecon que F.1/F.2 : ne pas armer une
detection sans mesurer le rayon de souffle).

| Constat | Fichier | Patch | Mesure |
|---|---|---|---|
| xdr-bruteforce-vpn-src-ip-vs-remip | oms-xdr/oms_xdr/rules.yaml:56-61 | `entity_field: src_ip` -> `remip` | 0 entite sur 58 docs |
| xdr-lateral-entity-user-vs-entity-user | rules.yaml:193-198 | `entity_field: user` -> `entity_user` | 0 entite sur 4 docs |
| xdr-portscan-fw-mauvais-stream | rules.yaml:31-36 | `stream: windows` -> `stream: ""` (interne) | 0 doc via son stream |

Idem F.1 (S_PSSCRIPTBLOCK) + F.2 (CR_EXECUTION_C2) deja documentes dans le plan : a livrer
ensemble, sous decision RSSI.

## B. Actions exigeant l'API Graylog (operateur/console)

- **regle-morte-incident** : retirer la regle `event_source==incident` du stream Interne et
  la regle `NOT event_source==incident` du stream M365 (flux mort depuis le 02/07). Le
  correctif structurel (catch-all Interne, LOT E) les rend inutiles.
- **Def "kill-chain correlee" (F.3)** : le script est deja corrige (commentee), mais
  l'instance vivante 6a2d2af7... reste ENABLED tant que l'operateur ne la desactive pas via
  l'API (ensure_event est early-skip). PUT state=DISABLED ou suppression.
- **m365-groupby-src-ip-jamais-peuple** (def 6a3aa906...) : retirer `src_ip` du group_by
  (garder `[user]`) ; src_ip jamais peuple sur M365 -> bucket (Empty Value). Cosmetique.
- **seal-hyp007-actor-usercode-partiel** (def 6a575000...) : 35 % des docs sans
  actor_usercode -> completer le mapping pipeline SEAL ou grouper aussi sur une cle presente.

## C. LOT E — Routage event_source (RC-2), la cause racine active

La fuite (alert_triage -> omni-m365/365j) est structurelle : taxonomie en DOUBLE liste
(Interne OR 25 regles / M365 NOT 26 regles), qu'aucun mecanisme ne synchronise. Le correctif
est ATOMIQUE et touche l'ingestion (risque R2) : **il ne doit pas etre fait en autonomie**.

- E.1 Interne en catch-all (`AND input==GELF NOT m365 NOT forti_dhcp NOT seal`) — liste de 52
  a 3.
- E.2 M365 en positif (`AND input==GELF AND event_source==m365`) — innocuite mesuree : 0 doc
  M365 sans le champ (0,000000 %).
- E.3 Dashboard `84-dashboards-triage-site.sh:20-22` dans le meme deploiement (sinon KPI a 0).
- E.4 Centraliser dans `lib-graylog.sh` (`ensure_event_source_routing()`) + liste canonique
  unique — **sans E.4, la classe reviendra** (deja corrigee le 13/06, revenue).

Verification J+1 : `graylog_*/_count` ~= 8 (pas de milliers) ; omni-interne recoit
alert_triage ; omni-m365 n'en recoit plus ; les 4 KPI restent non nuls.
Decision : reindexer les 85 458 docs deja fuites ou documenter la borne (reco : documenter).

## D. Decisions RSSI (rappel)

Montee Graylog 7.1.5 (mongodump prealable) ; accepter la hausse de volume mail (fin des
suppressions silencieuses) ; CR_EXECUTION_C2 (join meme-hote ou retrait) ; notifier
xdr_incident critical (prerequis : FP LSASS BX-WDSMDT-IT) ; activer ANTHROPIC_API_KEY
(gouvernance, apres verrou de caviardage) ; retrait total de
TRIAGE_FP_ENTITIES=src_ip=10.94.30.13.

## E. Lookups / doc / SEAL — a completer avec une donnee de Julien

- **net-segment-octet-10-absent-lookup** : ajouter la ligne VLAN 10 a
  `lookups/net-segments.csv` — Julien doit d'abord qualifier ce que porte le VLAN 10
  (27 docs/30j tombent dans un segment non libelle).
- **seal ACC-004 / ALM-004 group_by** : regrouper sur un champ peuple (`seal_Number` pour
  ACC-004, `REEV_CODE+seal_site` pour ALM-004) — a valider sur la donnee des deux sites.
- **doc-acc007 / FAUX-POSITIFS.md** : re-mesurer et dater la ligne ACC-007 (valeurs du jour :
  39 alertes / 26 badges sur 7 j).
- **guidance : entrees manquantes** (volume_drop, ...) et **orpheline** (kerberos_spray) :
  maintenance du lookup, non bloquant.
- **triage-gray-default-mort** : `OMNI_TRIAGE_GRAY_DEFAULT` est documente (38-alert-triage.sh)
  mais non implemente. Trancher : implementer la variable, ou retirer la doc.

## F. Deja traite ce tour (pour memoire)
Emoji guidance (siem_maintenance) et gabarits mail (13-graylog-alerts.sh) ; motif mort 7045 ;
plafond _msg_excerpt ; score borne a 100 ; parite texte/HTML (MITRE, "Recu car", liens) ;
_USER_FIELDS/_HOST_FIELDS (+entity_user/dark_host/cert_machine) ; bouton FP sur NOISE escalade ;
ZON-001 parquee ; stubs de reponse honnetes (oms-xdr + oms-graph) ; F.3/F.5 ; veille de version ;
clause "credential" nue retiree ; graylog-server en apt-mark hold.
