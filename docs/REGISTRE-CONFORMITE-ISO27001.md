# Registre de conformité ISO/IEC 27001:2022 — SIEM OMNITECH

*Version 1.0 — 12/06/2026 — Périmètre : supervision, journalisation et
détection assurées par le SIEM Graylog `bx-it-graylog-vm`. Classification : interne.*

Légende statut : ✅ Conforme · 🟡 Partiel (action en cours) · ⬜ À traiter.

## 1. Mesures organisationnelles (A.5)

| Mesure A.5 | Exigence | Mise en œuvre (preuve) | Statut |
|---|---|---|---|
| 5.7 Renseignement sur les menaces | Threat intelligence | Lookups Tor/Spamhaus, GeoIP, règles `threat_intel` | ✅ |
| 5.15 Contrôle d'accès | Restreindre l'accès | Console restreinte « Admins du domaine » via LDAPS (LDAPS.md), pare-feu hôte | ✅ |
| 5.16 Gestion des identités | Identités traçables | Auth AD nominative sur la console (backend LDAPS) | ✅ |
| 5.17 Authentification | Secrets gérés | LDAPS + `admin` local de secours au coffre ; secrets chmod 600 | ✅ |
| 5.18 Droits d'accès | Moindre privilège | Comptes de service dédiés (svc_siem), pas de collecte sous compte admin | ✅ |
| 5.23 Sécurité des services cloud | Surveillance du cloud | Collecte M365 (connexions, audit, Exchange/SharePoint) | ✅ |
| 5.25 Appréciation des événements | Qualifier/classer | Triage PRO §3, classification PRO §7, 88 définitions priorisées | ✅ |
| 5.26 Réponse aux incidents | Procédure + réponse | Playbooks PRO §6, matrice RACI §8, **SOAR-light** (blocage auto IP attaquantes via feed FortiGate) | ✅ |
| 8.16 (détection interne) | Détecter l'intrusion | **Compte canari AD** (leurre, faux positifs ~nuls) | ✅ |
| 5.28 Collecte de preuves | Preuves exploitables | Journaux horodatés UTC, export Graylog, rétention contrôlée (STD §9) | ✅ |
| 5.33 Protection des enregistrements | Intégrité des logs | Rétention auto, suppression hors-rétention impossible sans droits, purge tracée | ✅ |
| 5.36 Conformité aux politiques | Revue régulière | Revues PRO §2 + **rapport hebdomadaire automatique** (preuve) | ✅ |

## 2. Mesures liées aux personnes (A.6)

| Mesure | Exigence | Mise en œuvre | Statut |
|---|---|---|---|
| 6.3 Sensibilisation | Information | Charte informatique (journalisation), POL §11 | 🟡 (charte hors SIEM) |
| 6.8 Signalement d'événements | Remontée | Notifications mail + Teams SOC vers l'équipe IT | ✅ |

## 3. Mesures physiques (A.7)

| Mesure | Exigence | Mise en œuvre | Statut |
|---|---|---|---|
| 7.4 Surveillance physique | — | Hors périmètre SIEM (logs contrôle d'accès/NVR collectés via FortiGate) | 🟡 |

## 4. Mesures technologiques (A.8) — cœur du dispositif

| Mesure A.8 | Exigence | Mise en œuvre (preuve) | Statut |
|---|---|---|---|
| 8.5 Authentification sécurisée | Auth robuste console | LDAPS/TLS, cert vérifié par Root CA, accès limité aux admins | ✅ |
| 8.6 Gestion des capacités | Dimensionner/surveiller | Plan de capacité (STD §5), garde-fou disque `32`, KPI hebdo | ✅ |
| 8.7 Protection contre les codes malveillants | Détecter | FortiGate UTM (AV/IPS), Defender, règles ransomware/PowerShell/LSASS | ✅ |
| 8.8 Gestion des vulnérabilités techniques | — | OpenVAS (logs collectés) ; patching hors SIEM | 🟡 |
| 8.9 Gestion de configuration | Config maîtrisée | **IaC** : scripts 10→34 idempotents, sauvegarde de config quotidienne | ✅ |
| 8.10 Suppression d'informations | Effacement à terme | Rétention automatique par index (POL §4, `31`) | ✅ |
| 8.12 Prévention fuite de données | Détecter exfiltration | M365 (partage externe, transfert mail), FortiGate (threat intel sortant) | ✅ |
| 8.13 Sauvegarde | Sauvegarder/tester | Sauvegarde config chiffrée externalisée (`30`), PRA, **test à réaliser** | 🟡 |
| 8.15 Journalisation | Produire/protéger les logs | 7 inputs, 13 streams, 144 règles de pipeline, rétention POL §4, STD complet | ✅ |
| 8.16 Activités de surveillance | Surveiller/alerter | **88 définitions** (87 détections + 1 système), dashboard 24 pages, notifications, auto-surveillance | ✅ |
| 8.17 Synchronisation des horloges | Horloge commune | NTP sur toutes les sources, UTC dans le SIEM (STD §7) | ✅ |
| 8.20 Sécurité des réseaux | Cloisonner | VLAN 220 dédié, règles FortiGate par flux, pare-feu hôte | ✅ |
| 8.23 Filtrage web | — | FortiGate webfilter/DNS filter (logs collectés) | ✅ |
| 8.28 Codage sécurisé | — | Hors périmètre (logs CI/CD non couverts) | ⬜ |

## 5. Synthèse des actions ouvertes

| # | Action | Réf | Responsable | Échéance |
|---|---|---|---|---|
| 1 | Faire signer la POL par la DSI | POL §12 | DSI | — |
| 2 | Réaliser le test de restauration (PRA) | PRA, A.8.13 | Admin SIEM | Trimestre en cours |
| 3 | Décaler le job Veeam *Backup Copy* (contention de verrou de point de restauration ; la sauvegarde **aboutit au retry**, pas un trou de PRA) | Détection Veeam | Admin Sys | — |
| 4 | Étendre la collecte aux serveurs Windows restants + activer les SACL d'audit fichier sur les dossiers sensibles | STD §1 / `59` | Admin Sys | — |
| 5 | Chiffrement au repos `/data` (LUKS2/TPM2) | A.8.24, PROCEDURE-CHIFFREMENT | Admin SIEM | ✅ **Fait le 2026-06-14** |
| 6 | Affecter les comptes analystes au rôle Graylog « lecture seule » (créé) | A.8.2 | Admin SIEM | — |
| 7 | Activer l'API NinjaOne → SOAR avancé (isolation hôte / désactivation compte) | SOAR-PLAYBOOKS | Admin SIEM | — |
| 8 | Lier la charte informatique (sensibilisation 6.3) | A.6.3 | DSI | — |

> *Clôturé 2026-06-14* : Compte canari AD (en production, cf. §1 A.8.16 + REPONSE-AUTOMATISEE) ; création du rôle Graylog lecture seule (action #6 = affectation des comptes restante) ; intégrité/valeur probante des journaux (registre haché-signé) ; **chiffrement au repos `/data` (LUKS2 + déverrouillage TPM2) réalisé**.

## 6. Méthode de preuve pour l'auditeur

| Question type auditeur | Où montrer la preuve |
|---|---|
| « Que journalisez-vous ? » | STD §1 + §3bis (matrice EventID) |
| « Combien de temps ? Pourquoi ? » | POL §4 (rétentions justifiées CNIL/ANSSI) |
| « Comment détectez-vous ? » | DOSSIER §6 (88 définitions) + dashboard live |
| « Qui traite, en combien de temps ? » | PRO §2/§3/§7 + registre de traitement |
| « Prouvez la revue régulière » | Rapport hebdo (mail + copie `/var/backups/siem/`) |
| « Et si le SIEM tombe ? » | PRA + sauvegarde quotidienne + alerte d'absence |
| « Qui accède au SIEM ? » | LDAPS.md (restriction admins) + logs d'accès console |
| « Intégrité des preuves ? » | STD §9 + purge tracée/alertée |

*Revue de ce registre : à chaque audit interne et au minimum annuellement.*

## 7. Journal de maintenance (preuves d'exploitation A.8.15 / A.8.16 / A.8.17)

| Date | Action | Justification / portée | Contrôle |
|---|---|---|---|
| 2026-06-14 | **Purge des index de logs** (données + historique d'alertes ; **configuration conservée**) | Action de **maintenance planifiée** : remise à zéro après tuning anti-faux-positifs (le jeu de données initial était pollué par des FP de comptes de service/machine et des scripts internes légitimes). Reconstitution propre via `54-post-purge-repopulate.sh`. Coupure de collecte : nulle (ingestion reprise immédiatement dans des index vides). | A.8.15 (rupture d'audit-trail tracée et justifiée) |
| 2026-06-14 | **Correctif horodatage FortiGate** : `timestamp` posé depuis `eventtime` (epoch ns) | Avant : Graylog repliait sur l'heure de réception (+ ~14k erreurs/j). Après : **heure d'événement exacte** (écart résiduel 0,2 s) ; erreurs supprimées. | A.8.17 (synchronisation horaire / exactitude des horodatages) |
| 2026-06-14 | **Audit de dérive d'horloge inter-sources** (read-only) | Écart heure-événement / heure-réception mesuré par source : FortiGate 0,2 s, vSphere 1 s, Windows/Sysmon 5-7 s, BunkerWeb 7,6 s — **toutes < 8 s** (seuil 60 s). SIEM : NTP actif/synchronisé. **Aucune dérive significative.** | A.8.17 |
| 2026-06-14 | **Réduction des faux positifs** (audit multi-agent) + **routage 2-tiers des alertes** (mail = critique only, Teams = firehose) | Améliore la pertinence de la détection (A.8.16) et garantit que les alertes critiques ne sont pas noyées (preuve de revue exploitable). | A.8.16 / A.5.25 |
| 2026-06-14 | **Intégrité / valeur probante des journaux** : registre haché-en-chaîne signé HMAC (`60-integrity.sh`), copie hors-bande SMB, vérification hebdo + alerte sur rupture de chaîne ; **rôle Graylog lecture seule** (moindre privilège) | Fait passer la protection des journaux de « écriture seule » à **inaltérabilité prouvable** (tamper-evidence) ; réduit la surface de manipulation par les comptes privilégiés. | A.8.15 / A.8.2 / A.5.28 |
| 2026-06-14 | **Couverture MITRE ATT&CK cartographiée** (44 techniques / 12 tactiques sur 14) + nouvelles détections (privilege escalation, M365 risk/brute, audit fichiers 4663/5145, intégrité, exposition Internet) | Mesure et extension explicites de la couverture de détection ; aide à la priorisation. | A.8.16 / A.5.7 |
| 2026-06-14 | **Purge d'hygiène Vaultwarden** : ~46 M documents de rejeu mal routés supprimés (Filebeat rejouait l'historique du conteneur 2023→2026) ; règle de drop ajoutée + **index set dédié** | Restaure la qualité des agrégats de détection ; les événements internes/Windows réels sont préservés ; rupture d'audit-trail tracée et justifiée. | A.8.15 |
| 2026-06-14 | **Chiffrement au repos `/data` RÉALISÉ** (LUKS2 inline, aes-xts 512 bits + déverrouillage TPM2/PCR7). Méthode : reformatage chiffré à neuf — les logs indexés ont été repurgés puis repeuplés (ingestion live + `54`), toute la config (MongoDB, scripts, lookups) étant hors `/data` est intégralement préservée. Header sauvegardé chiffré hors-bande (SMB `/SIEM/luks/`), passphrase de secours au coffre, déverrouillage auto TPM2. | Protège les données au repos contre le vol de disque / mise au rebut / SAV / vol du serveur éteint. | A.8.24 / A.5.33 |

*Limites connues (backlog durcissement) : flux syslog ESET/vSphere/FortiGate en clair sur le VLAN SIEM isolé (migration syslog-over-TLS à étudier) ; SOAR avancé (isolation hôte / désactivation compte) en attente de l'API NinjaOne ; TPM en banque PCR SHA-1 (activer la banque SHA-256 au BIOS pour durcir le scellement — non bloquant).*
