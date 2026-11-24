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

Pour composer aussi une page dans `/soc/`, suivre
[le guide des pages et widgets](../docs/CONSOLE-MODULES.md). L'administrateur choisit
les streams, les filtres et les droits de consultation ; l'installation du pack
ne publie pas automatiquement de page SOC.
