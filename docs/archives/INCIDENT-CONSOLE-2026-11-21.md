# Incident du 21/11/2026 : tests de la console écrits en production

Document daté, non mis à jour. Heures en heure locale (CET, UTC+1) sauf mention
contraire.

## Résumé

Pendant le chantier « console d'administration », les tests de la console ont
été exécutés sur le serveur de production. Ils ont écrit dans l'état réel du
backend et un drop-in systemd ajouté pendant ce chantier a rendu le service
`omni-mobile-api` (backend de la console SOC) indisponible de 15:28 à 19:52.
Un message de test est resté dans Graylog ; il est conservé volontairement.

## Chronologie

| Heure | Fait | Source |
|---|---|---|
| 15:25:01 | Une fixture de test écrit un événement d'audit d'administration (`soar_unblock 8.8.8.8` par `lab-admin`) envoyé à Graylog | Graylog, voir ci-dessous |
| 15:25 à 15:28 | Les tests écrivent leurs artefacts dans `/var/lib/omni-mobile/admin` (répertoire d'état réel du backend) | artefacts conservés dans la sauvegarde |
| 15:28:08 | Un drop-in `20-depot-reference.conf` pointe `omni-mobile-api` vers `/opt/omni-siem/repository/mobile/.venv/bin/python`, qui n'existe pas ; le service redémarre et échoue en boucle (`status=203/EXEC`, « No such file or directory ») | `journalctl -u omni-mobile-api` |
| 15:28 à 19:52 | Backend de la console indisponible | idem |
| 19:52:06 | Restauration : drop-in et artefacts de test déplacés, service redémarré avec succès | idem, horodatage de la sauvegarde |

## Restauration

Le drop-in et les artefacts ont été déplacés, sans suppression, dans
`/home/siem-backup/incident-console-20261121` :

- `20-depot-reference.conf` : le drop-in fautif ;
- `admin-artefacts-test/` et `admin-dir-retire/` : contenu de
  `/var/lib/omni-mobile/admin` écrit par les tests (`audit.jsonl`, `exec/`).

## Correctifs dans le dépôt

- Chemins d'état du backend paramétrables (`MOBILE_SUBS_FILE`,
  `MOBILE_CASES_FILE`, `MOBILE_WATCH_FILE`, `SOC_REQ_DIR`, `SOC_ADMIN_DIR`) dans
  `mobile/omni-mobile-api.py`.
- Garde `OMNI_TEST_MODE=1` : le backend (`mobile/omni-mobile-api.py`) et
  l'exécuteur (`mobile/omni-soc-admin-exec`) refusent de démarrer si un chemin
  d'écriture vise la production.
- Isolation des tests : `tests/conftest.py` impose `OMNI_TEST_MODE=1` à tous les
  tests et dirige chaque chemin d'état et l'envoi GELF vers un répertoire
  temporaire.

Voir aussi [CONSOLE-DEPLOIEMENT.md](../CONSOLE-DEPLOIEMENT.md) pour le mode test.

## Message de test conservé dans Graylog

Un seul document `event_source:soc_admin` existe pour le 21/11/2026 ; il
provient de la fixture de test. Il n'a eu **aucun effet SOAR réel** : aucun
événement SOAR ni aucune ligne de journal système ne mentionne `8.8.8.8` ce
jour-là (vérifié le 22/11/2026 en lecture seule).

Identification :

| Champ | Valeur |
|---|---|
| `timestamp` | `2026-11-21 14:25:01.965` (UTC), soit 15:25:01 CET |
| `event_source` | `soc_admin` |
| `source` | `omni-soc-console` |
| `soc_action` / `soc_target` | `soar_unblock` / `8.8.8.8` |
| `soc_user` | `lab-admin` |
| `soc_request_id` | `20261121-152501-c1e2c9af` |
| `soc_result` | `transmise (page SOAR)` (libellé produit par la fixture) |
| `message` | `SOC admin execution soar_unblock 8.8.8.8 par lab-admin` |
| `gl2_message_id` | `01M7Z7Y3GD0041V4BSV6NKBZ83` |
| Index | `omni-m365_111` (reçu par l'input « M365 (GELF HTTP 12201) », stream « OMNI - M365 ») |

Recherche Graylog : `event_source:soc_admin AND soc_user:lab-admin AND soc_target:"8.8.8.8"`.

Raison de la conservation : **intégrité des journaux**. Les index sont tenus en
écriture seule (voir la [politique de rétention](../securite-conformite/POLITIQUE-RETENTION.md)
et la [procédure d'intégrité](../securite-conformite/PROCEDURE-INTEGRITE-PREUVE.md)) ;
supprimer un événement, même erroné, altérerait la valeur probante de
l'ensemble. Le document reste donc en place, il est identifié ici comme trace de
test et doit être écarté de toute analyse d'activité d'administration réelle.
Il disparaîtra avec son index, au terme de la rétention d'`omni-m365`.
