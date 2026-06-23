#!/bin/sh
# Genere une config Docker depuis la config repo (URLs internes au reseau compose,
# LLM desactive dans le conteneur) puis lance la boucle de correlation.
set -e

python - <<'PY'
import yaml
c = yaml.safe_load(open("/app/config.yaml")) or {}
g = c.setdefault("graylog", {})
g["opensearch"] = "http://opensearch:9200"          # lecture OpenSearch interne
og = g.setdefault("output_gelf", {})
og["host"] = "graylog"; og["port"] = 12201; og["proto"] = "http"   # reinjection GELF interne
c.setdefault("ollama", {})["enabled"] = False       # pas de LLM (Ollama) dans le conteneur
# Teams reste pilote par la config (enabled:false par defaut) + env OMS_TEAMS_WEBHOOK.
yaml.safe_dump(c, open("/tmp/config.docker.yaml", "w"), allow_unicode=True, sort_keys=False)
print("[oms-xdr] config.docker.yaml: opensearch:9200, gelf graylog:12201, ollama off")
PY

INT="${OMS_INTERVAL:-300}"
echo "[oms-xdr] boucle de correlation toutes les ${INT}s (Ctrl-C pour arreter)"
# NB : les IDs de streams de config.yaml correspondent a la prod -> exact apres un RESTORE DR.
while true; do
  python -m oms_xdr.engine --once --config /tmp/config.docker.yaml || echo "[oms-xdr] cycle en erreur (on continue)"
  sleep "${INT}"
done
