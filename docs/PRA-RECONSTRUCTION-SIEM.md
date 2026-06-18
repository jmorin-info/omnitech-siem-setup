# PRA — Plan de reconstruction du SIEM sur un nouveau serveur

*Version 1.0 — 12/06/2026 — Classification : interne — Réf ISO A.8.13, A.5.30*

Ce document décrit la **remise en service du SIEM sur un serveur de
remplacement** en cas de perte de la VM `bx-it-graylog-vm`. Il complète la
procédure technique détaillée `RESTORE.md` (commandes exactes) par le cadre
de continuité : objectifs, scénarios, rôles, validation.

## 1. Objectifs de continuité

| Indicateur | Valeur cible | Justification |
|---|---|---|
| **RTO** (reprise de la collecte) | ≤ 4 h | après mise à disposition d'une VM conforme |
| **RPO config** (perte de configuration) | ≤ 24 h | sauvegarde quotidienne 03:15 |
| **RPO logs** (perte d'historique) | jusqu'à la dernière rétention | les **journaux ne sont pas sauvegardés** (choix assumé : volume) — seule la configuration l'est |

**Conséquence clé** : après reconstruction, toute la chaîne de collecte, les
détections, dashboards et alertes reprennent à l'identique ; l'historique des
logs antérieurs est perdu mais la collecte temps réel redémarre immédiatement
(les agents/forwarders pointent sur le même FQDN/IP).

## 2. Pré-requis disponibles en permanence (à vérifier maintenant)

| Élément | Emplacement | Vérifié |
|---|---|---|
| Archives de config chiffrées (14 j) | `\\10.33.50.5\Public\SIEM\omni-siem-config_*.tar.gz.enc` | rotation OK |
| **Passphrase de déchiffrement** | Coffre-fort (`BACKUP_PASSPHRASE`) | ⚠️ À DÉPOSER AU COFFRE |
| Mot de passe `admin` local de secours | Coffre-fort | ✅ |
| Identifiants `svc_siem` (SMB) | Coffre-fort | ✅ |
| Procédure technique | `RESTORE.md` (inclus dans l'archive) | ✅ |
| Réservation IP/DNS `10.33.220.10` / FQDN | DNS interne + /etc/hosts | ✅ |
| **Clé HMAC d'intégrité** `/etc/graylog/omni-integrity.key` | Coffre-fort + hors-bande | ⚠️ sans elle, la chaîne d'intégrité passée n'est plus **vérifiable** (perte de valeur probante) |
| **Passphrase de secours LUKS `/data`** + **sauvegarde chiffrée du header** (header **inline** ; `omni-luks-header-*.img.enc`) | Passphrase → Coffre-fort ; header → SMB `/SIEM/luks/` (+ inclus dans le backup config chiffré quotidien) | ⚠️ sans la **passphrase**, `/data` est irrécupérable si le TPM/carte mère change ; le header inline est **sauvegardé/restaurable** (`luksHeaderRestore`) |

> Sans la passphrase de sauvegarde, les archives sont **irrécupérables**.
> Idem pour la **clé HMAC d'intégrité** (vérification de l'audit-trail) et la
> **passphrase/header LUKS** (déchiffrement de `/data` sur nouveau matériel — le
> TPM est lié à la carte mère, ré-enrôlement requis au remplacement). Ces 4 secrets
> sont les points de défaillance unique du PRA : présence au coffre vérifiée à
> chaque revue trimestrielle.

## 3. Scénarios et déclenchement

| Scénario | Réponse |
|---|---|
| VM corrompue / disque système perdu, `/data` intact | Reconstruire l'OS + pile, restaurer la config, **re-pointer `/data`** (logs conservés) |
| Perte totale (VM + données) | Reconstruction complète, logs repartent de zéro |
| Indisponibilité temporaire (service planté) | Pas de PRA : `systemctl restart` ; cf. PRO §4 |

Déclenchement : décision de l'**Admin SIEM** (incident d'exploitation) ou de
la **DSI** (sinistre majeur). Prévenir l'équipe IT (les alertes vont cesser
pendant la bascule).

## 4. Procédure de reconstruction (résumé — détail dans RESTORE.md)

1. **Provisionner** une VM Debian 12+, **même hostname/IP** (`bx-it-graylog-vm`
   / 10.33.220.10), VLAN 220, disque data sur `/data`.
2. **Installer la pile** aux versions de référence (DOSSIER §2 : Graylog
   7.1.3, OpenSearch 2.19.5, MongoDB 8.0.24, nginx) + `cifs-utils`.
3. **Récupérer et déchiffrer** la dernière archive depuis le partage SMB
   (compte `svc_siem`, passphrase du coffre).
4. **Restaurer** : fichiers `/etc` (graylog, opensearch, nginx, systemd),
   `/usr/local/sbin`, kit `/kit`, IaC `~/omnitech-siem-setup`, puis
   `mongorestore` de la base `graylog` (gestion de l'auth Mongo : RESTORE §4).
5. **Démarrer** mongod → opensearch → graylog-server → nginx ; réactiver les
   timers `omni-*`.
6. **Vérifier** (cf. §5).

## 5. Validation post-reconstruction (checklist)

- [ ] Console accessible en HTTPS, login AD (LDAPS) **et** `admin` local OK.
- [ ] Inputs à l'écoute : `ss -tlnp | grep -E "5044|1514|1516|12201"`.
- [ ] Les agents Winlogbeat se reconnectent (recherche `source:*` < 5 min).
- [ ] FAZ et vSphere émettent (streams FortiGate / vSphere alimentés).
- [ ] Collecteurs M365 : timers actifs, dernier run OK.
- [ ] 88 définitions d'événements présentes et **activées**.
- [ ] Dashboard « OMNI - SOC » s'affiche (24 pages).
- [ ] Sauvegarde : `bash 30-backup-config.sh` réussit (dépôt SMB).
- [ ] Une notification de test arrive par mail **et** Teams.
- [ ] `/data` : indices présents (si conservés) ou recréés ; rétentions OK.

## 6. Bascule et communication

- Pendant la reconstruction, **aucune alerte n'est émise** : surveiller
  manuellement les points critiques (AD, VPN) via les consoles natives
  (FortiGate, Entra) jusqu'au rétablissement.
- À la fin : informer l'équipe IT du rétablissement ; consigner l'incident
  et le temps de reprise réel (mesure du RTO) dans le registre d'incidents.

## 7. Maintien en condition du PRA

| Action | Fréquence |
|---|---|
| Vérifier la présence des 14 archives sur le partage | Mensuelle (PRO §2) |
| Vérifier la passphrase et les secrets au coffre | Trimestrielle |
| **Test de restauration réel sur VM jetable** | ≥ 1×/an (exigence A.8.13) |
| Mettre à jour les versions de référence (DOSSIER §2) | À chaque montée de version |

Un PRA non testé n'est pas un PRA : le test annuel est **obligatoire** et son
compte-rendu est conservé comme preuve d'audit.
