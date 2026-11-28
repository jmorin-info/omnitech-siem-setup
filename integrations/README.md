# Catalogue des intégrations

Chaque dossier contient un manifeste versionné et des exemples synthétiques.
Les Content Packs natifs (input, stream, pipeline et dashboard) sont générés
de façon reproductible, sans identifiants d'une installation existante.

```bash
python3 tools/omni-integrations.py list
python3 tools/omni-integrations.py validate
python3 tools/omni-integrations.py export unifi --output /tmp/unifi-r2.json
```

La révision 2 des trois modules a réussi une recette native sur Graylog 7.2.2
dans une VM Ubuntu 26.04 isolée : installation des packs, réception de dix messages
UDP synthétiques, normalisation, routage et exécution des six widgets de chaque
dashboard. Voir [la qualification](../docs/QUALIFICATION-UBUNTU2604.md).
Les formats constructeur couverts sont explicités dans la procédure ; la collecte
sur les équipements et versions du site reste à valider avant production.

La [procédure complète](../docs/INTEGRATIONS-MODULAIRES.md) décrit l'installation,
les paramètres réseau, les limites de parsing/rétention, la désinstallation et
l'ajout d'un constructeur. Aucune notification ni action SOAR n'est activée par
ces modules.

## Socle SOC piloté par les sources du site

`sources.json` décrit les sources (Windows, Sysmon, WatchGuard, FortiGate, M365, Linux…)
et les fonctions SOC (définitions d'alerte, oms-xdr, SOAR…) ; `socle/dashboards.json` décrit
le dashboard « OMNI - SOC » (vue d'ensemble, collecte, authentifications, postes, M365,
Linux, détections), chaque page et chaque widget déclarant ses sources (`requires`).
La clé `site` de `/etc/omni-siem/integrations.json` (voir `site-config.example.json`) liste
les sources et fonctions du site : seuls les pages et widgets correspondants sont publiés,
et la console `/soc/` masque les pages des sources absentes (`GET /m/api/site`), affiche
« non configuré » au lieu d'un zéro et liste toutes les entrées qui reçoivent des données.

```bash
python3 tools/omni-integrations.py soc-validate                       # contrat hors ligne (CI)
python3 tools/omni-integrations.py soc-sources --api URL/api ...      # sources observées (lecture)
python3 tools/omni-integrations.py soc-dashboards --api URL/api ...   # plan (lecture)
python3 tools/omni-integrations.py soc-dashboards --api URL/api ... --apply --backup-dir DIR
python3 tools/omni-integrations.py soc-check --api URL/api ...        # chaque widget exécuté
python3 tools/omni-integrations.py restore-dashboards socle --api URL/api ... --backup-dir DIR --apply
```

Le contrat refuse un widget qui lit un champ qu'aucune de ses sources ne produit, une source
inconnue ou un widget limité aux sources sans `requires`. Sans clé `site`, tout reste actif
(comportement historique) et `14-graylog-dashboards.sh` continue de produire « OMNI - SOC » ;
avec elle, ce script s'arrête sans rien toucher.

Pour composer aussi une page dans `/soc/`, suivre
[le guide des pages et widgets](../docs/CONSOLE-MODULES.md). L'administrateur choisit
les streams, les filtres et les droits de consultation ; l'installation du pack
ne publie pas automatiquement de page SOC.
