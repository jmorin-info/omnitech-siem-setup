# Audit de cohérence dépôt / production — 21/11/2026

Périmètre : dépôt `origin/main` (198e625, worktree `chantier/coherence`) comparé à l'état réel de
`bx-it-graylog-vm`, plus les incohérences internes au dépôt. Toutes les constatations ont été
faites en **lecture seule** (cat, sha256sum, `systemctl show/cat/list-*`, `journalctl`, `dpkg-query`,
`git --no-optional-locks`, API Graylog en GET). Aucune action n'a été exécutée en production.

Outil livré pour rejouer les contrôles : `tools/omni-coherence-check.py` (voir § 7).

## 1. Synthèse

Le code **déployé** est, à un fichier près, identique au dépôt : les 247 entrées du manifeste sont
identiques en SHA-256 après recopie de l'épinglage APT (seul écart, production plus récente), et
les 30 fichiers de `/var/www/siem-soc` sont identiques à `mobile/soc/`. Le problème n'est donc pas
une divergence de contenu mais une **divergence d'emplacement** :

- **9 unités systemd** (dont les moteurs `oms-xdr`, `oms-graph`, `oms-ml`, le backend de la console,
  la sauvegarde de configuration et le garde-disque) s'exécutent depuis l'ancienne copie `/root/omnitech-siem-setup`, avec ses venvs ; aucun venv
  n'existe dans le dépôt de référence `/opt/omni-siem/repository`.
- **25 scripts** de `/usr/local/sbin` codent en dur un chemin de cette copie (23 y lisent
  `00-vars.env`) ; le dépôt lui-même contient 126 occurrences de ce chemin
  dans 88 fichiers.
- Le contrôle de dérive hebdomadaire (`omni-drift-check`) compare la production à cette copie
  obsolète et émet chaque semaine une **fausse alerte critique**.
- Les 59 modifications non commitées de cette copie ne contiennent **aucun travail à récupérer** :
  chaque version présente sur disque existe déjà dans l'historique Git.
- `GRAYLOG_API_URL` dans `00-vars.env` (sans suffixe `/api`) est **incompatible** avec
  `lib-platform.sh` (198e625) : les appels `api_*` reçoivent la page HTML de l'interface. Cela rend
  dangereux tout repointage naïf des services vers le dépôt de référence (voir E4).
- Côté Graylog, 22 objets en service sont introuvables dans le dépôt (balayage IKE, scan WAF 404,
  lecture LAPS, 4 règles FP…), et l'intégration de l'orchestrateur de certificats (script 99)
  décrite dans la documentation n'est pas appliquée.
- La documentation annonçait des chiffres périmés (197 détections, 15 inputs, 22 streams,
  « 37 robots », Graylog 7.1) : corrigés dans ce chantier.

### Les 10 écarts les plus importants

| # | Écart | Gravité |
|---|---|---|
| E1 | 9 unités systemd lancées depuis `/root/omnitech-siem-setup` (ExecStart/WorkingDirectory), venvs uniquement dans cette copie | Critique |
| E2 | `omni-drift-check` compare la production à la copie obsolète : fausse alerte critique hebdomadaire (`omni-alert-triage`) et bruit « 54 modifiés + 5 non suivis » | Élevée |
| E3 | 25 scripts déployés codent en dur des chemins de `/root/omnitech-siem-setup` (dont `00-vars.env` lu par 23 d'entre eux) | Élevée |
| E4 | `GRAYLOG_API_URL` sans `/api` : `lib-platform.sh` construit des URL invalides ; piège pour `32-disk-guard.sh` (purge d'urgence silencieusement inopérante) si le service est repointé | Élevée |
| E5 | Objets Graylog en service sans source dans le dépôt : balayage IKE, scan WAF 404 (25/10 min), lecture LAPS (règles `omni-v3-laps-lecture*`), 4 règles `omni-fp-26-*`, détections SEAL DMS par site | Élevée |
| E6 | `oms-seal-sla.timer` désactivé alors que SEAL SLA-001/002 sont actives : ces détections ne peuvent jamais se déclencher | Élevée |
| E7 | Couche LLM du triage indisponible (crédit du fournisseur épuisé) : décisions retombées en « zone grise par défaut » | Élevée |
| E8 | Orchestrateur de certificats (script 99) documenté comme actif mais absent en production (ni input UDP 12201, ni stream, ni règles `omni-cert-*`) | Moyenne |
| E9 | Configuration nginx en service non versionnée (vhost modifié à la main, zones de limitation `omni_auth`/`omni_api`, `sw-retire.js`) | Moyenne |
| E10 | `omni-incident-correlate.timer` désactivé alors que `GUIDE.md` l'annonce toutes les 15 min ; `oms-maj-siem` jamais exécuté depuis son installation | Moyenne |

## 2. Tableau détaillé des écarts

Légende « qui » : **Admin** = administrateur de production ; **RSSI** = décision sécurité ;
**Dépôt** = mainteneur du dépôt (ou chantier de réorganisation).

### 2.1 Code déployé vs dépôt (contrôle 1)

| Réf. | Gravité | Constat | Preuve | Correctif proposé | Qui |
|---|---|---|---|---|---|
| D1 | Faible (corrigé) | `deploye/apt/oms-siem-series` épinglait `7.1.*`, la production `7.2.*` (production plus récente) | `./synchro-manifeste.sh` → `DIFFERENT deploye/apt/oms-siem-series` | Recopié dans le dépôt (commit « Recopie l'épinglage APT… ») ; état désormais : 247 identiques | Fait |
| D2 | Moyenne | `/usr/local/sbin/oms-regroupe-index` (14/11, regroupement d'index) en service mais absent du dépôt | `git ls-files \| grep regroupe` → vide | Le versionner sous `deploye/sbin/` (outil ponctuel : le marquer comme tel) puis `./generer-manifeste.sh` | Dépôt |
| D3 | Moyenne | Drop-ins hors manifeste : `graylog-server.service.d/10-omni-deps.conf`, `opensearch.service.d/override.conf`, `logstash.service.d/override.conf` | `tools/omni-coherence-check.py --controles non-suivis` | Versionner sous `deploye/systemd/` et étendre `generer-manifeste.sh` | Dépôt |
| D4 | Moyenne | nginx : `sites-enabled/graylog` est un fichier régulier (pas un lien), différent de `sites-available/graylog` (71 lignes de diff) ; zones `limit_req` (`/etc/nginx/conf.d/omni-ratelimit.conf`) et `sw-retire.js` introuvables dans le dépôt | `git grep -n limit_req` → vide ; `ls -la /etc/nginx/sites-enabled` | Versionner le vhost en service et la limitation de débit sous `deploye/nginx/` ; documenter que `05-nginx-tls.sh` n'est plus la source du vhost | Dépôt |
| D5 | Faible | `/var/www/siem-mobile` : `icon-*.png`, `chart.min.js`, `sw-retire.js` absents de `mobile/www/` (PWA retirée) | comparaison SHA-256 | Archiver `mobile/www/` comme « retirée » (voir § 6) | Dépôt |
| D6 | Info | `/var/www/siem-soc` (30 fichiers) : identique à `mobile/soc/` | `omni-coherence-check.py` (aucun écart console) | — | — |
| D7 | Info | `/opt/oms-seal-sla` : identique à `deploye/opt/oms-seal-sla` ; aucun autre `/opt/oms-*` | `ls -d /opt/oms-*` | — | — |
| D8 | Faible | `oms-xdr/deploy/oms-netscan-{full,quick}.{service,timer}` jamais installés (scan actif désactivé par décision « KEV + passif ») | `ls /etc/systemd/system/oms-netscan*` → absent | Les marquer explicitement « non déployés » dans `oms-xdr/README` | Dépôt |

### 2.2 Services lancés depuis une mauvaise copie (contrôle 2)

| Réf. | Gravité | Constat | Preuve | Correctif proposé | Qui |
|---|---|---|---|---|---|
| C1 | Critique | `omni-mobile-api`, `oms-xdr`, `oms-graph`, `oms-graph-respond`, `oms-ml-anomaly`, `oms-ml-fp` : ExecStart et WorkingDirectory dans `/root/omnitech-siem-setup` (venvs `mobile/.venv`, `oms-*/.venv`) | `grep -rn /root/omnitech-siem /etc/systemd/system` | Plan § 5, étapes 2 à 4 | Admin |
| C2 | Critique | `omni-backup-config` (`30-backup-config.sh`), `omni-disk-guard` (`32-disk-guard.sh`), `omni-iso-evidence` (`68-iso-evidence.sh`, écrit dans `/root/omnitech-siem-setup/docs`) lancés depuis la copie | idem | Plan § 5 ; prérequis E4 pour `32-disk-guard.sh` | Admin |
| C3 | Élevée | 25 scripts de `/usr/local/sbin` (`omni-ad-disable`, `omni-soar`, `omni-ueba-*`, `omni-ndr-*`, `siem-backup.sh`, `oms-snap-siem`…) codent ce chemin : 21 lisent `/root/omnitech-siem-setup/00-vars.env` directement ; `omni-alert-triage` lit `lookups/alert-guidance.json` dans la copie ; `omni-drift-check` et `omni-version-watch` ont `REPO = "/root/omnitech-siem-setup"` (et lisent `00-vars.env` par ce biais) ; `oms-snap-siem` ne le cite que dans un message | `grep -ln /root/omnitech-siem /usr/local/sbin/*` | Court terme : lien symbolique (plan § 5) ; cible : chemin unique configurable (`OMNI_VARS`, défaut `/opt/omni-siem/repository/00-vars.env`) | Dépôt puis Admin |
| C4 | Élevée | `omni-drift-check` : `[ECART] binaire: derive /usr/local/sbin/omni-alert-triage != depot triage/omni-alert-triage` — **faux positif** : le binaire en service est identique au dépôt de référence, seule la copie est ancienne | `cmp /usr/local/sbin/omni-alert-triage /opt/omni-siem/work/coherence/triage/omni-alert-triage` → identique | Résolu par le repointage (plan § 5) | Admin |
| C5 | Élevée | Le code du dépôt lui-même code ce chemin en dur : 126 occurrences dans 88 fichiers, dont `mobile/omni-mobile-api.py` (`OMS_GRAPH_DIR`, `MITRE_LOOKUP` par défaut), `generer-manifeste.sh` (entrée du backend), unités `deploye/systemd/oms-*.service` | `git grep -c /root/omnitech-siem` | Rendre ces chemins configurables (chantier séparé) ; mettre à jour `generer-manifeste.sh` après la bascule | Dépôt |
| C6 | Moyenne | `tools/install-console.sh` installe le backend dans `/opt/omni-siem/console` avec le `python3` système : `pywebpush` (push web) n'y est pas, et `mobile/` n'a pas de `requirements.txt` | `grep -n pywebpush mobile/omni-mobile-api.py` ; `ls mobile/requirements*.txt` → absent | Ajouter `mobile/requirements.txt` (pywebpush) et un venv dans l'installateur | Dépôt |
| C7 | Info | Aucune crontab ne référence les copies | `grep -rn /root/omnitech-siem /etc/cron* /var/spool/cron` → vide | — | — |

#### Inventaire des copies du dépôt (au 21/11/2026)

| Copie | HEAD | Branche | Retard sur 198e625 | État | Utilisée par la production |
|---|---|---|---|---|---|
| `/opt/omni-siem/repository` | 198e625 | main | 0 | propre | non (aucun service) |
| `/root/omnitech-siem-setup` | 897a2ac | main | **12** commits (5 sur son `origin/main` local périmé c72d434, puis 7) | 22 M, 32 D, 5 non suivis | **oui** (9 unités, 25 scripts) |
| `/root/omnitech-siem-merge` | c72d434 | fusion-20261111 (worktree de la précédente) | 7 | propre | non |
| `/root/omnitech-siem-purge` | 897a2ac | main | 12 | propre | non |

Autres éléments sous `/root` liés au dépôt : `/root/omni-v3/` (sources v3, `v3_build.py` identique à
`tools/omni-v3/v3_build.py` ; `tools/omni-v3/retour.sh` exécute depuis ce dossier),
`omnitech-siem-setup-20260622-2037.bundle`, 12 sauvegardes `omni-alert-triage.*bak*`.
L'image `omni-luks-header-2026-06-14.img` est une sauvegarde d'en-tête LUKS : **à conserver**
(hors périmètre du nettoyage, à stocker hors machine).

#### Les 59 modifications non commitées de `/root/omnitech-siem-setup`

Méthode : pour chaque fichier modifié ou non suivi, `git hash-object` puis recherche du blob dans
l'historique du dépôt de référence (`git cat-file -e`).

| Catégorie | Fichiers | Constat |
|---|---|---|
| 22 « modifiés » | README*, docs/*, `triage/omni-alert-*`, `mobile/soc/index.html`, `sync-deploye.sh`, `deploye/sbin/oms-snap-siem`… | Tous les contenus existent dans l'historique (e1bf665, 349719b, c72d434, 897a2ac…) : versions **plus anciennes** que 198e625 (ex. README.md : −244 lignes). `30-backup-config.sh` et `mobile/omni-mobile-api.py` sont identiques à 198e625. |
| 32 « supprimés » | `tools/alertes-v2/*`, `tools/omni-v3/*`, `tools/dashboards/*-20261111.py`, unités `omni-alert-lot*`, `omni-soc-actions*` | Tous présents dans 198e625 : l'arbre de travail est un instantané antérieur à leur ajout. |
| 5 non suivis | `mobile/soc/{icons/,manifest.webmanifest,sw.js}` ; `00-vars.env.avant-a2-20261111-2043` ; `30-backup-config.sh.avant-a2-20261111-2043` | Icônes et manifest identiques à 198e625 ; `sw.js` = version c72d434 ; `30-backup…avant-a2` connu (a9422da). Seule la sauvegarde datée de `00-vars.env` est inconnue de Git, **par conception** (secrets) : à garder dans la sauvegarde chiffrée, jamais dans le dépôt. |

**Conclusion : aucun travail utile non versionné à récupérer.** Le code réellement exécuté depuis
cette copie (`mobile/omni-mobile-api.py`, `oms-xdr`, `oms-graph`, `oms-ml`, `lookups/`, scripts 30, 32
et 68) est identique à 198e625 (`diff -rq` hors `.venv`, caches et `.bak`).

### 2.3 Graylog en service vs scripts (contrôle 3)

Mesures par `api_get` (GET) le 21/11/2026 :

| Objet | En service | Documentation avant correction |
|---|---|---|
| Version Graylog / OpenSearch / MongoDB | 7.2.2 / 2.19.7 / 8.0.38 (= `stack-versions.env`) | README FR/EN : « Graylog 7.1 » à 4 endroits, CONTEXT.md : 7.1.3 |
| Inputs | 14 | 15 |
| Streams | 21 (18 `OMNI - *` + 3 système) | 22 |
| Pipelines | 40 | 40 |
| Règles de pipeline | 277 | — |
| Définitions d'événements | 211 = 210 détections (199 actives, 11 désactivées) + 1 intégrée Graylog | 197 (192 actives) |
| Index sets | 21 | — |
| Notifications | 6 | — |
| Tables de lookup | 34 (20 CSV dans `lookups/`) | 20 |

| Réf. | Gravité | Constat | Preuve | Correctif proposé | Qui |
|---|---|---|---|---|---|
| G1 | Élevée | `GRAYLOG_API_URL` (00-vars.env) vaut `https://${SIEM_FQDN}:9000` sans `/api` ; `lib-platform.sh` l'utilise tel quel → `api_get /system` renvoie la page HTML. 70 scripts sur 74 s'arrêtent proprement (`require_api`), mais `40-purge-logs.sh`, `32-disk-guard.sh`, `69-ad-response.sh`, `29-drift-check.sh` n'ont pas ce garde-fou. Les scripts SEAL (`regen-seal-identity.sh`, `provision_detections.py`) attendent au contraire l'URL **sans** `/api` | `grep -n GRAYLOG_API_URL lib-platform.sh seal/graylog/regen-seal-identity.sh` | Normaliser dans `lib-platform.sh` (ajouter `/api` s'il manque) **avant** toute bascule de service vers le dépôt de référence | Dépôt puis Admin |
| G2 | Élevée | Détections en service sans source dans le dépôt : « FortiGate : balayage IKE (>=10 échecs phase 1 / IP / 6h) -> SOAR » (seulement citée dans CHANGELOG), « WAF : scan applicatif (>=25 erreurs 404 / IP / 10 min) », « OMNI v3 - Lecture d'un mot de passe LAPS (hors équipe IT) » | `tools/omni-coherence-check.py --graylog` | Exporter la définition par l'API (GET) et la versionner dans le script de son domaine | Dépôt |
| G3 | Élevée | Règles de pipeline en service sans source : `omni-v3-laps-lecture`, `omni-v3-laps-lecture-it`, `omni-fp-26-adexplorer-dev-seal`, `omni-fp-26-expo-ztna-vaultwarden`, `omni-fp-26-lsass-ninjaone-metering`, `omni-fp-26-service-veeam-vss` | idem | Versionner sous `tools/alertes-v2/regles/` (ou futur emplacement) | Dépôt |
| G4 | Moyenne | Règles du dépôt absentes en service : `omni-cert-00-tag`, `omni-cert-05-sev-{eleve,moyen,info}`, `omni-cert-10-error` (script 99), `omni-identity-upn-mirror` (`seal/graylog/pipelines/13-identity-mirror.rule`) | comparaison `ensure_rule`/`.rule` ↔ `GET /system/pipelines/rule` | Décider : appliquer le script 99 ou le marquer « non déployé » ; idem pour la règle SEAL | RSSI / Admin |
| G5 | Faible | Titres assemblés dynamiquement (SEAL DMS-004 à 009 par site, FortiManager), inputs dont le titre n'existe que dans la doc (« ESET (Syslog TCP 1515) ») | idem | Aucun si la génération est voulue ; sinon aligner le titre sur le script | Dépôt |
| G6 | Info | 11 définitions désactivées : force brute portail VPN, « Nouveau pays » (fusionnée, documentée dans 13-graylog-alerts.sh), SEAL DMS-001 à 006/008, EVT-002 (remplacée par DQ-001), « v3 - Connexion admin RDP… » | `jq '.event_definitions[]\|select(.state=="DISABLED")'` | Revue périodique : supprimer ou documenter | RSSI |

### 2.4 Incohérences internes au dépôt (contrôle 4)

| Réf. | Gravité | Constat | Correctif | Qui |
|---|---|---|---|---|
| R1 | Moyenne (corrigé) | Chiffres périmés dans README.md / README.fr.md (détections, inputs, streams, robots, scripts, version Graylog, orchestrateur de certificats, port 5555 qui n'écoute pas, PWA `/m/` retirée) | Commit « Aligne les chiffres et versions des README sur la production » | Fait |
| R2 | Faible (corrigé) | Ancres cassées : `README.md#8-the-soc-console`, `README.fr.md#numéros-dupliqués--ordre-correct-dexécution` (tableau inexistant) | Commit « Corrige deux ancres Markdown cassées » | Fait |
| R3 | Moyenne | Numéros de scripts dupliqués : 38 (alert-triage, vuln-scan), 39 (alert-digest, collect-health), 40 (purge-logs, ueba-ndr), 48 (m365-fail-codes, ndr-scan), 49 ×3 (enrich-lots, expo-port-class, ldap-recon), 84 (dashboards-triage-site, kerberoast-dedup), 85 (detection-extra3, detections-backlog), 86 (detections-backlog2, services-versioning), 97 (enrich-alerts, multisite-soar). La doc n'en citait que 7 | `ls [0-9][0-9]-*.sh \| cut -c1-2 \| sort \| uniq -d` | § 6 (pas de renommage dans ce chantier) | Dépôt |
| R4 | Faible | Fichiers ponctuels datés à la racine : `deploy-ameliorations-2026-09-23.sh`, `fp-tuning-2026-09.sh`, `fp-tuning{2,3,4}-2026-09-23.sh`, `fix-tor-detection-groupby.sh`, `reclaim-shards-reindex.sh`, `revert-index-rotation-legacy.sh`, `sync-deploye.sh` (retiré, ne fait qu'échouer) ; sous `tools/` : `deploy-audit-fixes-2026-07-17.sh`, `upgrade-graylog-715.sh`, `dashboards/*-20261111.py` | `git ls-files \| grep -v / \| grep -vE '^[0-9]{2}-'` | § 6 | Dépôt |
| R5 | Faible (corrigé) | Makefile : `pwa-deploy` déployait une PWA que nginx redirige ; `api-restart` redémarrait un service qui n'exécute pas le code du dépôt ; `ml`, `ml-status`, `check-js` échouaient sur `oms-ml/.venv` absent | Commit « Neutralise les cibles Makefile… » | Fait |
| R6 | Faible | FR/EN désynchronisés : README.md 15 sections / README.fr.md 27 ; README.fr.md contient une section « Overview (English) » ; `docker/README-DOCKER.en.md` 60 lignes contre 108 ; `docs/CONSOLE-SOC.md`, `GUIDE-DEPANNAGE.md`, `00-INDEX.md`, `CHANGELOG.md` modifiés après leur version anglaise ; 22 documents FR sans version EN | script de comparaison (dates de commit, nombre de lignes) | Chantier documentation | Dépôt |
| R7 | Faible | Liens vers des scripts absents : aucun (seuls `seal/docs/preflight.json` et `recon-raw.json`, volontairement ignorés par Git, sont cités) | — | — | — |
| R8 | Faible | `CONTEXT.md` mélange en-tête d'architecture (« Graylog 7.1.3 », « 28 règles + 4 pipelines ») et journal daté : les chiffres historiques sont exacts à leur date mais l'en-tête est périmé | — | Dater l'en-tête ou renvoyer vers le README | Dépôt |

### 2.5 Timers et robots (contrôle 5)

`systemctl list-timers 'omni-*' 'oms-*'` : 51 timers ; `systemctl --failed` : aucune unité en échec ;
tous les services `omni-*`/`oms-*` ont `Result=success` ; `journalctl -p err --since "24 hours ago"` :
aucune entrée de niveau erreur. Les défaillances sont visibles dans les journaux des robots :

| Réf. | Gravité | Constat | Preuve | Lien avec un écart de code | Correctif | Qui |
|---|---|---|---|---|---|---|
| T1 | Élevée | `oms-seal-sla.timer` désactivé, jamais exécuté dans l'historique du journal, alors que SEAL SLA-001/002 sont actives | `systemctl is-enabled oms-seal-sla.timer` → disabled | La procédure `deploye/opt/oms-seal-sla/README.md` demande `enable --now` | Activer ou désactiver les deux définitions | RSSI / Admin |
| T2 | Élevée | Juge LLM du triage : « credit balance is too low » ; décisions `llm_erreur:HTTPError` / `llm_erreur:pause` | `journalctl -u omni-alert-triage --since "24 hours ago" \| grep juge` | Aucun ; dépendance externe | Recharger le crédit ou basculer sur le modèle local | Admin |
| T3 | Moyenne | `omni-incident-correlate.timer` désactivé, aucune exécution dans le journal ; `GUIDE.md` l'annonce « 15 min » | `systemctl list-unit-files omni-incident-correlate.timer` | Doc non alignée | Décider (remplacé par `oms-xdr` ?) puis aligner GUIDE FR/EN | RSSI |
| T4 | Moyenne | `oms-maj-siem.timer` (installé le 11/11) jamais déclenché : le 15/11 le timer n'a démarré qu'à 04:43, après la fenêtre 04:30 + 10 min, avec `Persistent=false` | `journalctl -u oms-maj-siem.timer --since 2026-11-11` | README : « chaque dimanche à 04:30 » | `Persistent=true` ou vérification manuelle au prochain dimanche | Admin |
| T5 | Moyenne | `omni-ti-feeds` : « urlhaus KO: HTTP Error 410: Gone » → 0 domaine URLhaus | `journalctl -u omni-ti-feeds -o cat \| grep -i urlhaus` | README annonce les domaines URLhaus | Remplacer le flux (export abuse.ch actuel) | Admin |
| T6 | Faible | `oms-ml-fp` : « Read timed out (read timeout=60) » vers OpenSearch à 03:41 | `journalctl -u oms-ml-fp` | — | Augmenter le délai ou décaler l'horaire | Admin |
| T7 | Faible | 20 unités ou drop-ins en mode 0600 → 30 379 avertissements « world-inaccessible » en 24 h | `journalctl --since "24 hours ago" \| grep -c world-inaccessible` | — | `chmod 644` (aucun secret dans ces fichiers à vérifier avant) | Admin |
| T8 | Info | `omni-self-health` supervise 18 robots (« 18/18 robots OK ») sur 51 timers | `journalctl -u omni-self-health -n 5` | La doc annonçait 37 | Étendre la liste ou documenter le périmètre | Dépôt |

## 3. Correctifs appliqués dans ce chantier (dépôt uniquement)

| Commit | Contenu |
|---|---|
| Ajoute l'outil de contrôle de cohérence… | `tools/omni-coherence-check.py`, `tests/test_coherence_check.py` |
| Corrige deux ancres Markdown cassées… | README.md, README.fr.md |
| Aligne les chiffres et versions des README… | README.md, README.fr.md |
| Neutralise les cibles Makefile… | Makefile |
| Recopie l'épinglage APT en service… | `deploye/apt/oms-siem-series` |
| Rapport d'audit de cohérence | ce document |

Aucun script n'a été déplacé ni renommé.

## 4. Décisions attendues de l'administrateur / RSSI

1. Valider le plan § 5 (fenêtre de maintenance courte, services non critiques en premier).
2. G2/G3 : versionner les objets Graylog créés à la main, ou les supprimer s'ils sont abandonnés.
3. G4/E8 : appliquer ou abandonner l'intégration de l'orchestrateur de certificats (script 99).
4. T1 : activer `oms-seal-sla.timer` ou désactiver SLA-001/002.
5. T3 : statut de `omni-incident-correlate` (remplacé ou à réactiver).
6. T2 : rétablir la couche LLM du triage.

## 5. Plan de remise en cohérence de la production (NON exécuté)

Principe : le code exécuté est déjà identique au dépôt de référence ; on change l'**emplacement**
sans changer le **contenu**, service par service, avec retour arrière immédiat. Toutes les
commandes sont à lancer en root, dans l'ordre, après validation.

### Étape 0 — Sauvegarde

```bash
B=/home/siem-backup/coherence-$(date +%Y%m%d-%H%M); install -d -m 700 "$B"
tar --exclude='*/.venv' --exclude='*/__pycache__' -czf "$B/copies-root.tgz" -C /root \
    omnitech-siem-setup omnitech-siem-merge omnitech-siem-purge omni-v3
tar -czf "$B/systemd.tgz" -C /etc/systemd system
tar -czf "$B/nginx.tgz" -C /etc nginx
git -C /root/omnitech-siem-setup status --porcelain > "$B/setup-status.txt"
sha256sum /root/omnitech-siem-setup/00-vars.env /opt/omni-siem/repository/00-vars.env > "$B/vars.sha256"
```

### Étape 1 — Prérequis côté dépôt (commits, puis `git pull` dans `/opt/omni-siem/repository`)

1. **G1** : dans `lib-platform.sh`, `omni_api_setup`, ajouter après `API="${API%/}"` :
   `[[ "$API" == */api ]] || API="$API/api"` (les scripts SEAL retirent déjà ou n'ajoutent pas le suffixe : à vérifier par leurs tests).
   Sans ce correctif, **ne pas** repointer `omni-disk-guard` (purge d'urgence inopérante).
2. Ajouter `mobile/requirements.txt` (`pywebpush`) pour pouvoir recréer le venv du backend.
3. Vérifier : `bash run-tests.sh` vert ; `tools/omni-coherence-check.py --controles manifeste` sans écart.

### Étape 2 — Venvs dans le dépôt de référence (sans impact sur les services)

```bash
R=/opt/omni-siem/repository
for p in oms-xdr oms-graph oms-ml; do
  python3 -m venv "$R/$p/.venv" && "$R/$p/.venv/bin/pip" install -q -r "$R/$p/requirements.txt"
done
python3 -m venv "$R/mobile/.venv" && "$R/mobile/.venv/bin/pip" install -q pywebpush
# contrôle : mêmes versions que les venvs actuels
for p in oms-xdr oms-graph oms-ml mobile; do
  diff <(/root/omnitech-siem-setup/$p/.venv/bin/pip freeze | sort) <("$R/$p/.venv/bin/pip" freeze | sort) && echo "$p : venv identique"
done
```

### Étape 3 — Drop-ins de repointage (un service à la fois, du moins critique au plus critique)

Exemple pour `oms-graph` (même modèle pour `oms-graph-respond`, `oms-ml-anomaly`, `oms-ml-fp`, `oms-xdr`) :

```bash
install -d /etc/systemd/system/oms-graph.service.d
cat > /etc/systemd/system/oms-graph.service.d/50-depot-reference.conf <<'EOF'
[Service]
WorkingDirectory=/opt/omni-siem/repository/oms-graph
ExecStart=
ExecStart=/opt/omni-siem/repository/oms-graph/.venv/bin/python -m oms_graph.run analyze --push --config /etc/oms-graph/config.yaml
EOF
systemctl daemon-reload && systemctl start oms-graph.service && journalctl -u oms-graph -n 20 --no-pager
```

`oms-xdr` : `ExecStart=… -m oms_xdr.engine --once --config /opt/omni-siem/repository/oms-xdr/config.yaml`
(fichier identique à celui de la copie).

Backend console :

```bash
install -d /etc/systemd/system/omni-mobile-api.service.d
cat > /etc/systemd/system/omni-mobile-api.service.d/50-depot-reference.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/opt/omni-siem/repository/mobile/.venv/bin/python /opt/omni-siem/repository/mobile/omni-mobile-api.py
EOF
grep -q '^MITRE_LOOKUP=' /etc/default/omni-mobile || echo 'MITRE_LOOKUP=/opt/omni-siem/repository/lookups/mitre-attack.csv' >> /etc/default/omni-mobile
systemctl daemon-reload && systemctl restart omni-mobile-api && systemctl is-active omni-mobile-api \
  && curl -fsS http://127.0.0.1:8090/m/api/vapid >/dev/null && echo "backend OK"
```

Note : `OMS_GRAPH_DIR` reste codé en dur sur la copie dans `omni-mobile-api.py` ; l'étape 4 le couvre.

Scripts 30, 32, 68 (`omni-backup-config`, `omni-disk-guard` **après G1**, `omni-iso-evidence`) :

```bash
for u in omni-backup-config:30-backup-config.sh omni-disk-guard:32-disk-guard.sh; do
  s=${u%%:*}; f=${u#*:}; install -d /etc/systemd/system/$s.service.d
  printf '[Service]\nExecStart=\nExecStart=/usr/bin/bash /opt/omni-siem/repository/%s\n' "$f" \
    > /etc/systemd/system/$s.service.d/50-depot-reference.conf
done
# 68 écrit docs/EVIDENCE-AUDIT-<date>.md dans son répertoire de travail : prévoir un répertoire de sortie
# dédié (ex. /var/lib/omni-iso-evidence) plutôt que l'arbre Git de référence, puis repointer de la même façon.
systemctl daemon-reload
```

Retour arrière par service : `rm /etc/systemd/system/<svc>.service.d/50-depot-reference.conf && systemctl daemon-reload && systemctl restart <svc>`.

### Étape 4 — Chemins codés en dur restants (25 scripts, `OMS_GRAPH_DIR`, `REPO` de drift-check)

Transition sûre : remplacer l'ancienne copie par un lien vers le dépôt de référence, une fois
les étapes 1 à 3 validées pendant au moins un cycle complet de timers (24 h) :

```bash
mv /root/omnitech-siem-setup /root/omnitech-siem-setup.retire-$(date +%Y%m%d)
ln -s /opt/omni-siem/repository /root/omnitech-siem-setup
systemctl start omni-drift-check.service && journalctl -u omni-drift-check -n 20 --no-pager   # plus d'écart binaire
python3 /opt/omni-siem/repository/tools/omni-coherence-check.py                                # critiques attendus : 0
```

Retour arrière : `rm /root/omnitech-siem-setup && mv /root/omnitech-siem-setup.retire-* /root/omnitech-siem-setup`.
Cible (chantier dépôt) : lire `00-vars.env` via une variable `OMNI_VARS`, puis supprimer le lien.

### Étape 5 — Retrait des copies obsolètes (après 7 jours sans incident)

```bash
git -C /root/omnitech-siem-setup.retire-* worktree list            # vérifier le worktree « merge »
rm -rf /root/omnitech-siem-merge && git -C /root/omnitech-siem-setup.retire-* worktree prune
rm -rf /root/omnitech-siem-purge /root/omnitech-siem-setup.retire-*
# conserver : la sauvegarde de l'étape 0, /root/omni-luks-header-2026-06-14.img (à exporter hors machine)
```

Puis, côté dépôt : remplacer dans `generer-manifeste.sh` l'entrée
`/root/omnitech-siem-setup/mobile/omni-mobile-api.py` par le chemin de référence et régénérer le manifeste.

### Autres actions de production (indépendantes)

```bash
systemctl enable --now oms-seal-sla.timer            # seulement si décision T1 favorable
# T7 : lister d'abord les fichiers 0600 et vérifier qu'aucun ne porte de secret (Environment=…)
find /etc/systemd/system -maxdepth 2 -type f -perm 600 \( -name 'omni-*' -o -name 'oms-*' -o -path '*.d/*.conf' \) \
  -exec grep -l -iE 'Environment=.*(pass|secret|token|key)' {} +
# puis, pour les seuls fichiers sans secret : chmod 644 <fichier> ; systemctl daemon-reload
```

## 6. Recommandations de rangement (pour le chantier de réorganisation)

- **Doublons de numéros** (R3) : renuméroter le second de chaque paire dans des numéros libres
  (20, 23-26 sont libres) ou adopter un préfixe par domaine ; garder un tableau de correspondance
  ancien → nouveau dans la doc, car les journaux et CONTEXT.md citent les anciens numéros.
- **Ponctuels datés** (R4) : `archive/2026-09/` pour `fp-tuning*`, `deploy-ameliorations-*`,
  `fix-tor-detection-groupby.sh` ; `archive/2026-11/` pour `tools/dashboards/*-20261111.py`,
  `revert-index-rotation-legacy.sh`, `reclaim-shards-reindex.sh` ; supprimer `sync-deploye.sh`
  (stub qui échoue) après mise à jour des références.
- **PWA retirée** : déplacer `mobile/www/` vers `archive/` et retirer `PWA_WWW` du Makefile.
- **Outils hors manifeste** : versionner `oms-regroupe-index`, les drop-ins Graylog/OpenSearch/
  Logstash et la configuration nginx en service sous `deploye/` (D2 à D4).
- **`tools/omni-v3/retour.sh`** exécute depuis `/root/omni-v3` : le faire pointer vers `tools/omni-v3/`.

## 7. Outil `tools/omni-coherence-check.py`

Lecture seule, bibliothèque standard uniquement. Git est appelé avec `--no-optional-locks`
(l'index des copies n'est pas réécrit) ; l'API Graylog n'est interrogée qu'en GET ; aucun secret
n'est affiché.

```bash
python3 tools/omni-coherence-check.py                       # manifeste, non-suivis, copies, robots, versions
python3 tools/omni-coherence-check.py --graylog --vars /opt/omni-siem/repository/00-vars.env
python3 tools/omni-coherence-check.py --json --strict        # 2 = critique, 1 = élevée (strict), 0 = sain
```

Résultat le 21/11/2026 (après recopie de l'épinglage APT) : critique 15, élevée 28, moyenne 8,
faible 23 ; code retour 2. Les 15 critiques correspondent aux directives ExecStart/WorkingDirectory
de C1/C2 et disparaissent après les étapes 3 et 4 du plan.

Tests : `tests/test_coherence_check.py` (12 tests sur fixtures synthétiques, aucun accès au système
réel, dont un test qui vérifie qu'aucune commande d'écriture n'est émise). Suite complète :
`bash run-tests.sh` → 397 réussis, 12 ignorés, suites oms-ml/oms-xdr/oms-graph vertes.
