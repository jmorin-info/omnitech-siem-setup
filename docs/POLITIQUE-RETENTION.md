# Politique de rétention des journaux - OMNITECH Security (SIEM Graylog)

Référence ISO/IEC 27001:2022 — A.8.15 (Journalisation), A.8.16 (Surveillance),
A.8.17 (Synchronisation des horloges). Approche **risk-based** : la durée est
adaptée à la valeur sécurité/forensic de chaque source, dans la limite du
stockage disponible.

> Revue : 2026-06-14 — à valider et dater par le RSSI.

## Durées de conservation (en ligne, consultable)

Chaque source dispose d'un **index set dédié** (préfixe `omni-*`) avec rotation
journalière (`P1D`) et rétention exprimée en nombre d'index (1 index = 1 jour).
La rétention « supprime » (delete) les index une fois la fenêtre dépassée.

| Source                          | Index set        | Durée  | Justification                                                            |
|---------------------------------|------------------|--------|-------------------------------------------------------------------------|
| Windows Security (AD)           | `omni-winsec`    | 180 j  | Dossier sécurité : authentification, comptes, privilèges, PKI (6 mois)  |
| Sysmon (endpoint)               | `omni-sysmon`    | 90 j   | Détections, chasse, processus/réseau (hors bruit registre) ; gros volume — 90 j sous contrainte de capacité (cf. note capacité) |
| Windows autres (Veeam, ADCS…)   | `omni-winother`  | 90 j   | Sauvegardes Veeam, PKI/ADCS, services système ; 90 j sous contrainte de capacité |
| Microsoft 365 / Entra           | `omni-m365`      | 365 j  | Connexions cloud, partages, rôles, audit Entra ID (collecté en GELF)    |
| vSphere                         | `omni-vsphere`   | 180 j  | Accès hyperviseur, suppressions de VM (6 mois)                          |
| ESET PROTECT (EDR/AV)           | `omni-eset`      | 180 j  | Détections poste/serveur, valeur forensique élevée (syslog JSON) (6 mois) |
| FortiGate (pare-feu)            | `omni-fortigate` | 180 j  | Trafic volumineux : 6 mois de fenêtre forensic (relevé à 180 j le 14/08 pour la profondeur d'investigation d'intrusion) |
|                                 |                  |        | sécurité (deny/UTM/VPN) restent corrélables sur toute la fenêtre        |
| BunkerWeb (WAF)                 | `omni-bunkerweb` | 90 j   | Logs HTTP/WAF à fort volume ; 90 j couvrent le besoin d'investigation   |
| Vaultwarden (coffre MDP)        | `omni-vaultwarden` | 90 j | Coffre de mots de passe : échecs d'auth, accès admin. **Index dédié** pour éviter que le volume/rejeu n'évince les events internes du SIEM |
| FortiManager (admin/config)     | `omni-fortimanager` | 90 j | Journaux d'administration/configuration FAZ (changements, accès admin). **Index dédié** (créé par `63`). 90 j sous contrainte de capacité (à relever si besoin de traçabilité longue) |
| Interne SIEM (UEBA/ML/santé)    | `omni-interne`   | 90 j   | Événements réinjectés : scores UEBA/ML, SLA de collecte, santé robots, incidents XDR. 90 j couvrent l'analyse de tendance et l'entraînement ML (fenêtres ≤ 7 j). **Index dédié** (créé par `79`) |

Sources annexes :
- **NPS / RADIUS** : champs mappés et index prêts côté SIEM, mais la collecte
  n'est **pas encore activée côté client** (aucun volume à ce jour).
- **Télémétrie interne SIEM** (stream « OMNI - Interne SIEM » : santé collecte,
  disk-guard, contrôle de certificats) : conservée dans l'index set Graylog par
  défaut, rétention courte (gestion opérationnelle, pas de valeur d'audit long
  terme).

## Événements explicitement EXCLUS (risque accepté, faible valeur / fort volume)

La réduction de bruit est appliquée **au stage 30 du pipeline, APRÈS toute
détection** (script 41-retention-iso.sh) : elle ne casse aucune règle de
détection, elle évite seulement de stocker durablement des événements à fort
volume et faible valeur.

| Source           | Event                              | Motif                                                                                                       |
|------------------|------------------------------------|-------------------------------------------------------------------------------------------------------------|
| Sysmon           | EID 12 (RegistryEvent add/delete)  | ~62 % du volume Sysmon, bruit ; la persistance registre reste couverte par l'EID 13 (Value Set), conservé   |
| Windows Security | 4673 (Sensitive Privilege Use)     | Très volumineux, quasi-100 % bénin (services système)                                                        |
| Windows Security | 4627 (Group Membership)            | Redondant avec 4624 (déjà conservé)                                                                          |

Conservés volontairement malgré leur volume : **4662** (requis pour la détection
DCSync) et **4688** (traçabilité de création de processus).

## Intégrité & protection (A.8.15)
- Index OpenSearch en écriture seule (pas de modification a posteriori).
- Détection d'effacement de journaux (1102 / 4719 / 1100 / 104) -> alerte.
- Sauvegarde quotidienne de la configuration ; horloges synchronisées (NTP).
- Accès SIEM restreint (LDAPS, groupe AD dédié).
- Horodatage normalisé à la source de l'événement (ex. FortiGate : champ
  `eventtime`), garantissant l'ordre chronologique réel en forensic.

## Justification des durées (contrainte de capacité — A.8.15 risk-based)
Les durées ci-dessus résultent d'un arbitrage **risque × capacité disque** vérifié
le 14/08/2026. Une rétention uniforme de 365 j sur toutes les sources sécurité
demanderait **~9 To** — au-delà du disque `/data` de 7,3 To — donc irréaliste. Le
choix retenu : conservation la plus longue pour les sources à **plus forte valeur
de traçabilité et plus faible volume** (M365/Entra 365 j, SEAL 365-730 j), palier
**intermédiaire 180 j** pour les sources sécurité à volume moyen (Windows Security,
ESET, vSphere, FortiGate — 6 mois de fenêtre forensic), et **90 j** pour les sources
à très fort volume ou faible valeur unitaire (Sysmon, Windows autres, WAF/BunkerWeb,
Vaultwarden, DHCP, interne SIEM). Projection à rétention pleine : **~5,3 To ≈ 72 %**
du disque (réplicas = 0, mono-nœud), sous le seuil d'alerte de 80 %. Toute extension
d'une source à volume élevé (ex. Sysmon → 180 j) doit être validée par un recalcul
de capacité pour ne pas franchir le seuil de purge d'urgence (88 %).

## Garde-fou de capacité (disk-guard)
Disque **/data dédié, 7,3 To**. Le service `omni-disk-guard` (32-disk-guard.sh,
timer systemd toutes les 6 h) constitue le filet de sécurité ultime, au-delà de
la rétention nominale ci-dessus :

| Seuil d'occupation /data | Action                                                                                          |
|--------------------------|-------------------------------------------------------------------------------------------------|
| < 80 %                   | Rien : la rétention normale supprime les index à J+rétention                                     |
| ≥ 80 %                   | Alerte (GELF -> mail « Disque SIEM >80% ») — revoir le plan de rétention                         |
| ≥ 88 %                   | **Purge d'urgence** : suppression des index `omni-*` les plus ANCIENS (jamais l'index actif d'un flux) jusqu'à repasser sous **82 %**, + alerte |

Ce mécanisme s'interpose AVANT les watermarks OpenSearch (95 % = indices passés
en lecture seule = collecte stoppée). Revue mensuelle du Go/jour réel (cf.
supervision de la collecte). Au volume actuel, /data est occupé à ~2 % (147 Go).

---

_Document généré et maintenu par 41-retention-iso.sh — à valider et dater par le
RSSI. Voir aussi : POL-SUPERVISION-JOURNALISATION.md, INVENTAIRE-SOURCES.md,
ISO27001-MAPPING.md._
