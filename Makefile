# Makefile — raccourcis d'exploitation SIEM/console OMNITECH.
# Cibles courantes ; les scripts de provisioning restent les sources de vérité.
.DEFAULT_GOAL := help
SOC_WWW := /var/www/siem-soc
PWA_WWW := /var/www/siem-mobile
OMSML   := oms-ml/.venv/bin/python

.PHONY: help test ml ml-status ml-push fp-train console-deploy pwa-deploy api-restart check-js

help: ## Liste les cibles
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

test: ## Suite de tests hors-ligne (rédaction + oms-ml)
	@bash run-tests.sh

check-js: ## Vérifie la syntaxe JS de la console (esprima ES2017)
	@for f in mobile/soc/index.html mobile/www/index.html; do \
	  $(OMSML) -c "import re,esprima; src=open('$$f',encoding='utf-8').read(); js='\n'.join(re.findall(r'<script>(.*?)</script>',src,re.S)).replace('??',' || ').replace('?.','.'); esprima.parseScript(js); print('JS OK','$$f')"; \
	done

ml: ## Scoring d'anomalie ML (lecture seule, sans push)
	@cd oms-ml && .venv/bin/python -m oms_ml.run anomaly --entity all --top 12 --config /etc/oms-ml/config.yaml

ml-status: ## État des labels du modèle de réduction de FP
	@cd oms-ml && .venv/bin/python -m oms_ml.run status --config /etc/oms-ml/config.yaml

ml-push: ## Déclenche le scoring ML + réinjection GELF (prod)
	@systemctl start oms-ml-anomaly.service && echo "oms-ml-anomaly déclenché"

fp-train: ## (Ré)entraîne le modèle de réduction de FP (si assez de labels)
	@systemctl start oms-ml-fp.service && journalctl -u oms-ml-fp.service -n 5 --no-pager

console-deploy: check-js ## Déploie la console desktop vers nginx
	@install -m 644 mobile/soc/index.html $(SOC_WWW)/ && chown www-data:www-data $(SOC_WWW)/index.html && echo "console déployée → $(SOC_WWW)"

pwa-deploy: check-js ## Déploie la PWA mobile vers nginx
	@install -m 644 mobile/www/index.html $(PWA_WWW)/ && chown www-data:www-data $(PWA_WWW)/index.html && echo "PWA déployée → $(PWA_WWW)"

api-restart: ## Redémarre le backend de la console (omni-mobile-api)
	@python3 -m py_compile mobile/omni-mobile-api.py && systemctl restart omni-mobile-api && systemctl is-active omni-mobile-api
