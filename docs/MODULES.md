# Modules d'intégration : contrat v2

Ce document est la référence de tout module (pare-feu, EDR, RMM, annuaire, cloud…). Il généralise ce qui existait déjà :
le module `watchguard` (manifeste, `derived_fields`, catalogue de dashboards), `omni-integrations`,
`integrations/sources.json`, les détections par site, `omni-deploy` et `omni-update`. Rien n'est réécrit : les modules
historiques sont adoptés.

- Outil : `tools/omni-integrations.py modules list|validate|plan|apply|verify|rollback|uninstall`
- Code : `omni_integrations/modules.py`, garde shell `lib-modules.sh`
- Tests hors ligne : `tests/test_modules.py` (s'applique automatiquement à tout nouveau manifeste)
- Profils de site d'exemple : `integrations/profiles/`

## 1. Principes

1. **Un module = un dossier** `integrations/<id>/` avec `manifest.json` (+ `fixtures.json` si le module a un analyseur).
   Tout ce que le module installe est déclaré dans le manifeste.
2. **Activation par la configuration de site**, jamais par le code : clé `site.modules` de
   `/etc/omni-siem/integrations.json`. Sans cette clé (site historique), **tous les modules restent actifs**, comme avant.
3. **Module absent ou non configuré = rien ne casse** : unités systemd conditionnées, streams, dashboards, détections et
   pages de console non publiés, contrôles qui répondent « non configuré » au lieu d'échouer.
4. **Aucune valeur de client dans le dépôt** (nom, IP, ID Graylog, URL de tenant, secret). Exemples fictifs seulement.
5. **Lecture seule vers les API tierces** (scopes minimaux, aucune action côté éditeur).
6. **Secrets** : fichiers `root:root 0600` hors dépôt, référencés par la configuration de site ; jamais affichés,
   journalisés, passés en argument ni en `Environment=`. Lecture par `LoadCredential=` (recommandé) ou par chemin.

## 2. Manifeste (`schema_version: 2`)

Les manifestes `schema_version: 1` (unifi, paloalto) restent acceptés : ils sont lus comme un module `parser` qui fournit
la source `<id>`.

| Clé | Obligatoire | Contenu |
|---|---|---|
| `schema_version` | oui | `2` |
| `id` | oui | `[a-z][a-z0-9_]{1,31}`, égal au nom du dossier |
| `name`, `summary` | oui | libellé et une phrase |
| `revision` | oui | entier ≥ 1, **+1 à chaque changement** de ce que le module installe |
| `status` | oui | `stable`, `preview` ou `legacy` (objets encore créés par un script numéroté, adoptés par le module) |
| `compat` | oui | `{"omni_siem_min": "AAAA-MM-JJ", "graylog": ">=7.0,<8.0"}` |
| `depends`, `conflicts` | non | identifiants d'autres modules |
| `provides` | oui | `{"sources": […], "features": […]}` ; chaque source existe dans `integrations/sources.json` (clé `module` ou `integration` = id du module) |
| `site_config.schema` | non | `{<param>: {"type": "string|integer|boolean|list|object", "required": bool, "default": …, "pattern": "regex", "description": "…"}}` ; valeurs dans `integrations.<id>.parameters` |
| `secrets` | non | `[{"name", "description", "required", "default_path": "/etc/omni-siem/secrets/<id>/<nom>", "format"}]` ; chemin surchargeable par `integrations.<id>.secrets.<nom>` ; **jamais de valeur** |
| `inputs` | non | `[{"key", "type": "syslog_udp|syslog_tcp|gelf_http|gelf_udp|beats|raw_tcp|raw_udp", "default_port", "tls", "adopt", "legacy_title"}]` ; entrée du site désignée par `integrations.<id>.inputs.<key>` |
| `parser` | non | analyseur générique (regex, cef, csv) : Content Pack et règles `omni-integration-<id>-r<rév>-*` |
| `graylog` | non | objets adoptés ou créés : `streams`, `index_sets`, `pipelines`, `rule_prefixes`, `lookups` |
| `collectors` | non | `[{"unit", "timer", "files", "secrets", "enabled_by", "output"}]` ; chaque fichier figure aussi dans `manifeste-deploye.txt` ; `enabled_by` = paramètre booléen qui active un collecteur facultatif |
| `fields`, `field_prefixes` | oui sans `parser` | champs produits par la source ; préfixes des champs bruts (`eset_`) |
| `derived_fields` | non | champs ajoutés par d'autres couches (TI, détections), avec leur origine |
| `detections` | non | `{"sources": […]}` : `omni-site-detections` ne crée les détections que si la source est active |
| `dashboards` | non | catalogue de vues (format watchguard : `key`, `title`, `pages[].widgets[]`, `may_be_empty`, paramètres `{nom}`) |
| `console_pages` | non | pages de `/soc/` liées au module (déclarées dans `sources.json`) |
| `checks` | oui | contrôles post-déploiement (§4) |
| `rollback`, `uninstall` | oui | `{"objects": "by_id|by_name", "keeps_data": true, "notes": "…"}` |
| `legacy` | si `legacy` | `{"scripts": […], "to_split": […]}` : scripts numérotés protégés par `omni_module_enabled <id>` |

**Cohérence des champs (testée)** : tout champ lu par un widget du module, ou attendu par `sources.json` pour ses sources,
appartient aux champs produits (`fields`, analyseur, `derived_fields`, préfixes, champs communs). Les champs normalisés
reprennent les noms du socle (`event_source`, `event_action`, `src_ip`, `dest_ip`, `user`, `host`, `threat_name`…) ; les
champs bruts sont préfixés `<id>_` ; `event_source` vaut l'identifiant de la source.

## 3. Configuration de site (`/etc/omni-siem/integrations.json`, hors Git)

```json
{
  "schema_version": 1,
  "site": {"name": "Site exemple", "modules": ["watchguard", "bitdefender"],
           "sources": ["windows_security", "sysmon"], "features": ["deploy_kit"]},
  "integrations": {
    "bitdefender": {"parameters": {"api_url": "https://cloud.example.invalid/api"},
                    "secrets": {"api": "/etc/omni-siem/secrets/bitdefender/api"},
                    "inputs": {"gelf": "000000000000000000000000"}}
  }
}
```

- Sources effectives = `site.sources` ∪ sources fournies par les modules actifs (le socle SOC et la console les utilisent).
- `site.features` reste réservé aux **fonctions SOC** (detections, soar, xdr…) ; un module peut en fournir par `provides.features`.
  L'activation d'un module passe par `site.modules` : un même nom ne désigne pas à la fois une fonction et un module.
- Paramètre absent : valeur `default` ; paramètre `required` absent, valeur refusée par le motif, secret absent ou trop
  ouvert : module **bloqué** au plan, rien n'est appliqué.

## 4. Contrôles (`checks`)

Types : `secret`, `unit`, `stream_recent` (`stream`, `minutes`), `input_running` (`input`), `fields_present`
(`stream`, `fields`, `days`), `dashboards` (= `omni-integrations check`), `lookup` (`path`). Chaque contrôle porte
`severity` (`critique` ou `avertissement`) et éventuellement `when` (paramètre booléen). Module inactif : « non
configuré ». Sans `--api` : les contrôles Graylog répondent « non vérifié ». Code retour 1 si un contrôle critique échoue.

## 5. Unités systemd et fichiers déployés

- Nommage : `omni-<id>-<rôle>.service|.timer`, exécutable `/usr/local/sbin/omni-<id>-<rôle>`, défauts sans secret dans
  `/etc/default/omni-<id>-<rôle>`.
- Condition obligatoire dans chaque `.service` d'un module (vérifiée par les tests) :

  ```ini
  ConditionPathExists=|/etc/omni-siem/modules.d/<id>.enabled
  ConditionPathExists=|!/etc/omni-siem/modules.d
  ```

  L'unité démarre si le module est activé, ou si le site n'a pas encore de `modules.d` (site historique).
- Secrets : `LoadCredential=api:/etc/omni-siem/secrets/<id>/api`, lu dans `$CREDENTIALS_DIRECTORY/api`.
- `omni-deploy` ne pose pas les fichiers d'un module inactif (avertissement dans le plan, clé `module_skipped`) ; un
  fichier déjà présent reste mis à jour et n'est jamais supprimé par `deploy`.

## 6. Cycle de vie

| Étape | Commande | Effet |
|---|---|---|
| liste | `modules list` | modules, révision, statut, actif ou non, révision du marqueur |
| validation | `modules validate` | schéma, champs, secrets, unités conditionnées, dépendances (CI) |
| plan | `modules plan [--site-config F] [--root R]` | **lecture seule** : activer / mettre à niveau / reconfigurer / désactiver / inactif / bloqué ; fichiers, timers, objets Graylog, dashboards, pages, sources des détections |
| apply | `modules apply --apply` | marqueurs `/etc/omni-siem/modules.d/<id>.enabled` (révision + empreinte des paramètres), timers activés ou arrêtés, transaction dans `/var/lib/omni-siem-modules/` |
| verify | `modules verify [--api URL]` | contrôles des modules actifs |
| rollback | `modules rollback <transaction> --apply` | marqueurs et timers d'avant |
| upgrade | `omni-update plan` puis `apply-code`, puis `modules plan` et `modules apply --apply` | `omni-update plan` liste `modules_changed` (révision avant et après) |
| uninstall | `modules uninstall <id> --apply` | après retrait de `site.modules` : marqueur retiré, timers arrêtés ; objets Graylog retirés par ID (`uninstall` existant) ; index et messages conservés |

Sans `--apply`, tout est simulé. Avec `--root`, les commandes systemd sont seulement enregistrées (déploiement à blanc).
Les objets Graylog des modules à analyseur restent gérés par les commandes existantes (`adopt`, `dashboards`, `check`,
`restore-dashboards`, `uninstall`), le socle SOC par `soc-dashboards`, les détections par `tools/omni-site-detections.py`.

## 7. Nommage Graylog

Stream `OMNI integration - <Nom>` (nouveau module) ou titre historique conservé (`legacy`) ; index set `omni-<id>` ;
règles `omni-integration-<id>-r<rév>-*` (analyseur) ou `omni-<id>-*` ; définitions et vues `OMNI - <Nom> - …` ;
tables `omni-<id>-*`. Un retour arrière retire ses propres objets par ID ou par nom, jamais une collection entière.

## 8. Modules disponibles

| Module | Schéma | Statut | Ce qu'il porte |
|---|---|---|---|
| `watchguard` | 2 | preview | analyseur Fireware, Content Pack, 3 vues, pages, `derived_fields` TI |
| `fortigate` | 2 | legacy | entrées FortiAnalyzer (07), index set et stream (10), règles et pipeline (12), collecteur DHCP facultatif (56, `omni-fortidhcp-fetch`) |
| `eset` | 2 | legacy | entrée syslog, stream et index set ESET (52) ; règles `omni-eset-*` dans le pipeline partagé « OMNI - Sources externes » |
| `unifi`, `paloalto` | 1 | preview | analyseurs génériques |

## 9. Déployer sur un nouvel environnement

1. Installer le socle (voir `docs/INSTALLATION.md`) sans activer de module.
2. Choisir un profil dans `integrations/profiles/` (multisite FortiGate et ESET, ou PME WatchGuard), le copier dans
   `/etc/omni-siem/integrations.json` et remplacer les valeurs fictives (ID d'entrées, adresses, chemins de secrets).
3. Déposer les secrets demandés (`install -m 600 -o root -g root … /etc/omni-siem/secrets/<id>/<nom>`).
4. `omni-integrations modules plan` : corriger chaque défaut bloquant ; vérifier que seuls les modules voulus sont actifs.
5. `omni-integrations modules apply --apply` (note la transaction), puis lancer les scripts numérotés : les parties des
   modules inactifs sont sautées. Pour un module à analyseur : `adopt --apply` puis `dashboards --apply`.
6. `omni-deploy deploy --apply` : les fichiers des modules inactifs ne sont pas posés.
7. `omni-integrations soc-dashboards --apply` et `tools/omni-site-detections.py` : seules les sources actives sont publiées.
8. `omni-integrations modules verify --api https://127.0.0.1:9000/api`.

## 10. Écrire un nouveau module (NinjaOne, Bitdefender…)

1. `integrations/<id>/manifest.json` v2 ; la source dans `integrations/sources.json` avec `"module": "<id>"`.
2. Collecteur `deploye/sbin/omni-<id>-<rôle>`, unités conditionnées (§5), entrées dans `manifeste-deploye.txt`.
3. Exemple de configuration (valeurs fictives) dans `integrations/profiles/`.
4. Tests : `tests/test_modules.py` valide le manifeste sans rien ajouter ; ajouter les tests du collecteur (réponses
   d'API synthétiques, aucune écriture vers l'API).
5. Une section dans ce document (§8).
