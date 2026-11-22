# Scripts ponctuels (historique)

Ce dossier regroupe les scripts **à usage unique** : correctifs datés, passes de
réduction des faux positifs, migrations et retours arrière liés à un incident.
Ils ont été écrits pour une situation précise de la production et sont
**conservés pour la traçabilité** (ISO/IEC 27001, A.8.32 gestion des
changements) : ils documentent ce qui a été modifié, pourquoi et comment
revenir en arrière.

Ils ne font **pas** partie de l'installation ni des mises à jour. Ne pas les
relancer sans relecture : la plupart agissent sur des entités Graylog qui ont
évolué depuis. Les scripts de provisioning numérotés restent à la racine du
dépôt (voir [SCRIPTS-PROVISIONING.md](../../docs/reference/SCRIPTS-PROVISIONING.md)).

Chaque script se replace à la racine du dépôt au démarrage (`cd "$(dirname "$0")/../.."`)
et lit `00-vars.env` comme les scripts numérotés. Ceux qui l'indiquent sont en
simulation (DRY-RUN) par défaut et n'écrivent qu'avec `APPLY=1`.

## Inventaire et statut

Statut vérifié le 21/11/2026 en lecture seule (API Graylog en GET, OpenSearch
en GET, paquets installés). « Non vérifié » signifie que l'effet n'a pas pu être
constaté sans action en écriture ou sans analyse plus poussée.

| Script | Date | Objet | Statut constaté |
|---|---|---|---|
| `deploy-audit-fixes-2026-07-17.sh` | 17/07/2026 | Déploiement des correctifs de l'audit alerting/corrélation (voir [archive de l'audit](../../docs/archives/AUDIT-2026-07-17-RESTE-A-TRAITER.md)) | Non vérifié |
| `upgrade-graylog-715.sh` | 17/07/2026 | Montée Graylog 7.1.3 vers 7.1.5 | Dépassé : Graylog 7.2.2 installé |
| `seal-alert-tri.sh` | 21/07/2026 | Matrice de tri des détections SEAL (désactivation, retrait du mail) | Non vérifié |
| `seal-add-acc008.sh` | 07/2026 | Création de la détection SEAL ACC-008 | Appliqué : définition ACC-008 présente |
| `seal-qa-triage-gate.patch` | 07/2026 | Coupure du mail de triage pour le site SEAL de test | Appliqué : logique présente dans `triage/omni-alert-triage` |
| `fp-tuning-2026-09.sh` | 09/2026 | Réduction des faux positifs, passe 1 (Tor/Spamhaus, LSASS, TeamViewer, SEAL QA) | Appliqué : requête Tor filtrée sur `action:accept`, TeamViewer absent de la règle RAT/RMM |
| `fp-tuning2-2026-09-23.sh` | 23/09/2026 | Passe 2 (Entra Connect, SEAL EVT-001, vCenter) | Appliqué : EVT-001 non alertante, détection vCenter agrégée présente |
| `fp-tuning3-2026-09-23.sh` | 23/09/2026 | Passe 3 (authentification legacy M365, événement SOAR informatif) | Appliqué : « Authenticated SMTP » exclu, événement SOAR non alertant |
| `fp-tuning4-2026-09-23.sh` | 23/09/2026 | Passe 4 (connexions adm-* hors heures, enregistrement MFA M365) | Appliqué : les deux définitions sont non alertantes |
| `deploy-ameliorations-2026-09-23.sh` | 23/09/2026 | Triage, robot géographique, règle 4698 | Partiellement constaté : définitions 4698 présentes ; reste non vérifié |
| `fix-tor-detection-groupby.sh` | 09/2026 | Retrait de `ti_reputation` du regroupement de la détection SSL-VPN/Tor | Appliqué : regroupement `user, remip` |
| `revert-index-rotation-legacy.sh` | 09/2026 | Retour à la rotation quotidienne héritée après suppressions prématurées | Appliqué : jeux `omni-*` en rotation héritée, sans hiérarchisation |
| `reclaim-shards-reindex.sh` | 09/2026 | Consolidation par réindexation des index quasi vides | État compatible : un seul index par préfixe visé |

## Scripts retirés

Scripts de provisioning ou outils remplacés, archivés ici le 22/11/2026 sans
changement de nom pour conserver le lien avec l'historique, les journaux et les
documents datés. Avant l'archivage, une recherche a vérifié qu'aucune unité
systemd ni aucun exécutable en production (`/etc/systemd/system`,
`/usr/local/sbin`, `/etc/cron*`) ni aucun autre script du dépôt ne les appelle :
seuls des commentaires les citent. Ne pas les relancer.

| Script | Retiré le | Remplacé par | Remarque |
|---|---|---|---|
| `15-rapport-hebdo.sh` | 22/11/2026 | `34-weekly-report.sh` (`omni-weekly-report.timer`, lundi 08:00) | Le fichier qu'il installait, `/etc/cron.weekly/omni-siem-rapport`, était encore présent en production le 22/11/2026 : rapport hebdomadaire envoyé en double tant qu'il n'est pas retiré |
| `22-alert-routing.sh` | 27/06/2026 (archivé le 22/11/2026) | `38-alert-triage.sh` | Réduit à un message de dépréciation, sans action |
| `31-retention-iso.sh` | 22/11/2026 | `83-retention-consolidee.sh` | Valeurs du 12/06/2026 contraires à la politique de rétention actuelle |
| `44-incidents.sh` | 28/06/2026 (archivé le 22/11/2026) | `oms-xdr` | Se contentait de désactiver `omni-incident-correlate` |
| `sync-deploye.sh` | 12/11/2026 (archivé le 22/11/2026) | `synchro-manifeste.sh`, `generer-manifeste.sh` | Réduit à un message d'erreur de renvoi |

## Règles pour ce dossier

- Un script ponctuel porte sa date dans son nom ou dans son en-tête, décrit son
  contexte, son effet et son retour arrière.
- Il est idempotent et, s'il modifie la production, en simulation par défaut.
- Une fois appliqué, il n'est plus modifié, sauf pour corriger un chemin après
  une réorganisation du dépôt.
