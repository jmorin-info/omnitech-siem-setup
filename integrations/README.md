# Catalogue des intégrations

Chaque dossier contient un manifeste versionné et des exemples synthétiques.
Les Content Packs natifs (input, stream, pipeline et dashboard) sont générés
de façon reproductible, sans identifiants d'une installation existante.

```bash
python3 tools/omni-integrations.py list
python3 tools/omni-integrations.py validate
python3 tools/omni-integrations.py export unifi --output /tmp/unifi-r2.json
```

Les trois modules sont en préversion : leurs contrats de format sont testés hors
ligne et les 44 sources DSL ont été acceptées par les endpoints `/parse` de
Graylog 7.2.2 le 19 novembre 2026, sans création d'entité. L'import complet et la
qualification matérielle restent nécessaires avant production.

La [procédure complète](../docs/INTEGRATIONS-MODULAIRES.md) décrit l'installation,
les paramètres réseau, les limites de parsing/rétention, la désinstallation et
l'ajout d'un constructeur. Aucune notification ni action SOAR n'est activée par
ces modules.
