# Makefile — raccourcis d'exploitation SIEM/console OMNITECH.
# Cibles courantes ; les scripts de provisioning restent les sources de vérité.
.DEFAULT_GOAL := help
SOC_WWW := /var/www/siem-soc
PWA_WWW := /var/www/siem-mobile
# Interpréteur de oms-ml (venv créé hors Git) ; surcharger : make ml OMSML=/chemin/python
OMSML   ?= $(CURDIR)/oms-ml/.venv/bin/python
NEED_OMSML = @test -x "$(OMSML)" || { echo "venv oms-ml absent : $(OMSML) (créer oms-ml/.venv ou passer OMSML=...)" >&2; exit 2; }

.PHONY: help test ml ml-status ml-push fp-train console-deploy pwa-deploy api-restart check-js

help: ## Liste les cibles
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

test: ## Suite de tests hors-ligne (rédaction + oms-ml)
	@bash run-tests.sh

check-js: ## Vérifie la syntaxe JS de la console (esprima ES2017)
	$(NEED_OMSML)
	@for f in mobile/soc/index.html mobile/www/index.html; do \
	  $(OMSML) -c "import re,esprima; src=open('$$f',encoding='utf-8').read(); js='\n'.join(re.findall(r'<script>(.*?)</script>',src,re.S)).replace('??',' || ').replace('?.','.'); esprima.parseScript(js); print('JS OK','$$f')"; \
	done

ml: ## Scoring d'anomalie ML (lecture seule, sans push)
	$(NEED_OMSML)
	@cd oms-ml && "$(OMSML)" -m oms_ml.run anomaly --entity all --top 12 --config /etc/oms-ml/config.yaml

ml-status: ## État des labels du modèle de réduction de FP
	$(NEED_OMSML)
	@cd oms-ml && "$(OMSML)" -m oms_ml.run status --config /etc/oms-ml/config.yaml

ml-push: ## Déclenche le scoring ML + réinjection GELF (prod)
	@systemctl start oms-ml-anomaly.service && echo "oms-ml-anomaly déclenché"

fp-train: ## (Ré)entraîne le modèle de réduction de FP (si assez de labels)
	@systemctl start oms-ml-fp.service && journalctl -u oms-ml-fp.service -n 5 --no-pager

console-deploy: ## Déploie tous les assets et les routes de la console SOC
	@bash tools/install-console.sh --apply

pwa-deploy: ## RETIRÉE : /m/ redirige vers /soc/ depuis le 12/11/2026 (utiliser console-deploy)
	@echo "pwa-deploy est retirée : nginx redirige /m/ vers /soc/, $(PWA_WWW)/index.html n'est plus servi. Utiliser : make console-deploy" >&2; exit 2

api-restart: ## Redémarre le backend de la console (refusé s'il ne tourne pas depuis ce dépôt)
	@exe="$$(systemctl show omni-mobile-api.service -p ExecStart --value)"; \
	 case "$$exe" in *"$(CURDIR)/mobile/omni-mobile-api.py"*) ;; \
	 *) echo "omni-mobile-api ne tourne pas depuis $(CURDIR) (ExecStart : $$exe) : redémarrer n'appliquerait pas ce code. Voir docs/AUDIT-COHERENCE-2026-11-21.md." >&2; exit 2;; esac
	@python3 -m py_compile mobile/omni-mobile-api.py && systemctl restart omni-mobile-api && systemctl is-active omni-mobile-api
