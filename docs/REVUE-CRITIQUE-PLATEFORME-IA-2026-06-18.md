# Revue critique & synthèse — Plateforme de détection/réponse IA sur socle Graylog

**OMNITECH SECURITY — 2026-06-18 — destiné à : Julien Morin (RSSI/dev)**
**Objet :** réconcilier les 3 dossiers de recherche (`/tmp/prompt/compass_*.md`) avec l'état réel de
`omnitech-siem-setup`, en challenger les hypothèses, et trancher une séquence exécutable.
**Sources :** les 3 artefacts ; `CONTEXT.md` (1007 l.), `README.md`, `docs/`, inventaire script-par-script
(59 scripts / 10 238 lignes bash + 26 microservices Python `/usr/local/sbin/omni-*`).

---

## 0. Verdict en cinq décisions

1. **Les 3 docs raisonnent en greenfield ; ton système est en production et mûr.** Le « point de départ
   recommandé » du Doc 3 (PoC Kerberoasting → MVP read-only multi-cas, soit ses Lots 1-2, ~6 mois) est
   **déjà livré et dépassé**. Suivre la feuille de route à la lettre = reconstruire ce qui tourne.
2. **Le vrai périmètre neuf se réduit à 4 briques** : (a) couche LLM de triage, (b) actionneurs de réponse
   au-delà du blocage IP (isolation ESET, désactivation AD), (c) chaîne LLM cloud (anonymisation + ZDR) —
   **conditionnelle**, (d) scan de surface **actif** — **à déprioriser**. Tout le reste existe.
3. **Le risque #1 n'est pas l'IA, c'est l'absence totale de contrôle de version.** 10k lignes de sécurité
   de prod, zéro git, zéro test, zéro CI, un seul mainteneur. **C'est la priorité absolue, avant toute
   ligne d'IA**, et c'est aussi une preuve directe pour l'audit ISO (maîtrise du changement, clause 10).
4. **Commencer par le LLM *local* (Mistral/Ollama), pas par LLM cloud.** Il valide la valeur du triage sans
   dépendance contractuelle (ZDR), sans risque d'anonymisation, sans surface d'exfiltration. LLM cloud ne se
   justifie qu'**après** preuve de valeur locale **et** d'un cas que Mistral 7B échoue à traiter.
5. **LLM cloud n'apporte AUCUNE preuve requise pour l'audit de nov. 2026.** L'audit est servi par le SIEM
   existant + le dossier ISO déjà rédigé. La plateforme IA est un *plus*, hors chemin critique de l'audit,
   et ne doit pas le mettre en péril (c'est d'ailleurs ce que dit le Doc 3 — mais l'enthousiasme IA le noie).

---

## 1. Le décalage central : « à construire » vs « déjà en prod »

Les trois dossiers décrivent un BUILD comme si la couche détection/corrélation/réponse n'existait pas.
Réconciliation chiffrée (le % « déjà fait » est l'auto-évaluation de l'inventaire, corroborée par `CONTEXT.md`) :

| Ce que les docs proposent de « construire » | Réalité dans `omnitech-siem-setup` | Déjà fait |
|---|---|---|
| **PoC Kerberoasting** (Doc 3, Lot 1, point de départ) | Détection 4769 RC4 0x17 + SPN non-machine en prod, mappée T1558.003, **+ compte canari** avec SPN `MSSQLSvc` posé exprès comme appât (`35-canary.sh`) | **100%** |
| Microservice de **corrélation** multi-source (Doc 1, Obj 1) | `omni-incident-correlate` : agrège par entité, reconstruit la kill-chain (ordre canonique), score 0-100 par saturation, fenêtre 24h, ≥2 tactiques | **~70%** |
| **Détections Sigma / MITRE** (Doc 1 & 3) | 74 règles pipeline, ~54 techniques / 14 tactiques, export Navigator (`37`/`57`), enrichissement MITRE sur tout événement | **~85%** |
| **NDR / surveillance réseau** (Doc 1, Obj 2) | 4 services : beaconing C2 (coeff. de variation), DNS tunneling (entropie), scan réseau (T1046), impossible-travel (Haversine) | **~85%** |
| **SOAR / réponse semi-autonome** (Doc 1 & 2) | `omni-soar` : webhook → feed → deny FortiGate, **sans creds sur le FW**, TTL 24h, whitelist, seuil, cap/kill-switch, audit GELF | **~60%** |
| **Console unifiée « single pane of glass »** (Doc 2 & 3) | Dashboard SOC 19-21 pages (50 widgets), carte-cyber temps réel, drill-down Graylog natif | **~80%** |
| **Threat intel** (Doc 1) | Tor exit + Spamhaus DROP branchés, alerte sur hit IP publique | partiel (OSS) |
| **Rétention / intégrité ISO** (transverse) | Rétention par paliers, chaîne d'intégrité HMAC-SHA256 anti-altération (`omni-integrity`), PRA/PRO/POL rédigés | **~90%** |
| **Reporting** (Doc 2, KPI) | Rapport hebdo HTML + mensuel PDF (weasyprint) + KPI MTTD/posture | **~85%** |
| **Couche LLM (Mistral/Ollama)** | — | **0%** |
| **Couche LLM cloud + anonymisation Presidio + ZDR** | — | **0%** |
| **Actionneurs réponse** (ESET isolate, AD disable) | ESET ingéré comme *source de logs* (syslog 1515), **pas** d'API de réponse | **0%** |
| **Scan de surface ACTIF** (nmap/OpenVAS) | Cartographie *passive* (FortiGate, `49-expo-port-class`) + détection KEV/patch (`38`) ; aucun scanner actif | **0% (actif) / ~70% (passif)** |

**Lecture :** la feuille de route du Doc 3 (Lots 1→8) commence par reconstruire ce qui est, par sa propre
métrique, à 60-90 % livré. Le centre de gravité du projet doit basculer de « construire la détection » vers
« greffer une fine couche LLM + 2 actionneurs sur un socle qui marche déjà ».

---

## 2. Le vrai périmètre neuf (la liste de travail honnête)

1. **Service de triage LLM** — 27ᵉ microservice `omni-*`, même patron que les 26 autres (consomme OpenSearch,
   émet GELF). Net-new, mais petit. **Valeur : narratif d'incident pour le RSSI + triage des patterns
   nouveaux/ambigus non couverts par les règles + brouillon de plan de réponse.** C'est un *copilote*, pas
   un moteur.
2. **Actionneurs de réponse** — API ESET PROTECT (isolation/scan/kill) et désactivation AD. Net-new côté
   intégration, **mais la machine à états de sûreté existe déjà** dans `omni-soar` (cf. §4-H).
3. **Chaîne LLM cloud** *(conditionnelle)* — tokenisation déterministe + Presidio en filet + ZDR contractuel.
   À n'engager qu'après §0-4.
4. **Surface ACTIVE** *(à déprioriser)* — nmap/OpenVAS. Plus faible valeur ajoutée (le passif + KEV existent),
   plus fort risque opérationnel (prod fragile + 14 tunnels partenaires).
5. **Surface d'approbation humaine** — uniquement utile une fois (2) en place ; petite extension de la console.

Tout le reste des 3 docs est soit déjà fait, soit du *nice-to-have* (Grafana, CMDB, graphe topologie, iOS).

---

## 3. Réconciliation détaillée par objectif

### Doc 1 — Architecture (corrélation+LLM / surface / MXDR)

| Objectif | Position du doc | Écart avec le réel | Verdict |
|---|---|---|---|
| **Obj 1** Microservice corrélation + LLM | Construire un FastAPI qui poll `/events/search`, re-corrèle par clé/fenêtre, mappe MITRE, puis LLM | Corrélation + MITRE **déjà faits** (pipelines + `omni-incident-correlate`). Le doc risque de **dupliquer le moteur** (2ᵉ source de vérité = divergence) | Ne **pas** reconstruire la corrélation. Ajouter **un seul étage** : LLM en aval de `event_source=incident`. Garder l'idiome stdlib/timer, **pas FastAPI** (cf. §4-C) |
| **Obj 2** Surface d'exposition | Passif FortiGate + actif nmap/OpenVAS prudent | Passif **déjà fait** ; détection de scan **déjà faite** ; **actif = seule vraie nouveauté** | Garder le passif. Actif = **dernière priorité**, OpenVAS authentifié seulement si A.8.8 l'exige au-delà du KEV |
| **Obj 3** Reproduire ~70 % de Bitdefender MXDR | ~70 % reproductible, gaps durs = 24/7 humain + dark-web + garantie | Sur l'axe *technique*, tu es plutôt à **75-85 %** déjà (SIEM fort, NDR-logs+beaconing, SOAR-block, scoring, threat-intel). Les gaps durs sont exacts | Reframe : tu as **déjà bâti l'essentiel de la *techno* MXDR**. L'irréductible = le *service staffé* + l'*assurance*, pas la techno |

### Doc 2 — Intégration LLM cloud (hybride / Presidio / console / amélioration continue)

| Volet | Position du doc | Écart / critique | Verdict |
|---|---|---|---|
| **A** Routeur hybride Mistral/LLM cloud + tool gateway | Score de routage, machine à états d'approbation, anti-injection | Excellent sur le principe. **La machine à états existe en v1 dans `omni-soar`** (valide→politique→TTL/cap→exécute→audit) | **Généraliser `omni-soar`**, ne pas redessiner de zéro |
| **B** Anonymisation Presidio réversible | Presidio = colonne vertébrale, recall FR modeste | **Inversion nécessaire** : tes données sont surtout *structurées* (schéma de champs connu). Tokenisation **déterministe = colonne vertébrale** (100 % de recall sur les champs connus), Presidio = *filet* sur le texte libre (cmdline/message). Cf. §4-D | Adopter Presidio **en backstop**, pas en spine |
| **C** Console (Grafana + NestJS) | Tout assembler | Le « single pane of glass » **existe déjà** (dashboard SOC + carte). Grafana n'ajoute que des métriques infra (Centreon/Prometheus) | Console = **petite extension** (approbation + auth nominative), pas un chantier |
| **D** Amélioration continue + orchestration n8n/Ansible | Boucle fermée, Batch API nocturne | Le Doc 3 documente lui-même le **piège n8n** (abandon dès que conditionnels/état). Garder le complexe en code maîtrisé | n8n pour le linéaire simple uniquement ; Ansible pour la config idempotente |

### Doc 3 — Feuille de route (Lots 0-8)

| Lot | Position du doc | Réalité | Verdict |
|---|---|---|---|
| **0** Socle / anti-key-person (IaC, git, doc) | « transverse, démarrage immédiat » | **Sous-pondéré.** C'est en fait **LA priorité #1 et elle est urgente** : aucun git, aucun test (cf. §6) | **Remonter en P0 absolue** |
| **1** PoC Kerberoasting | point de départ | **Déjà en prod** | Sauter (mais propager la note calendrier RC4 2026, cf. §5) |
| **2** MVP read-only multi-cas | 10-15 règles Sigma | **74 règles déjà en prod** | Largement dépassé |
| **3** Couche LLM cloud + Presidio | mode conseil | Net-new, mais **commencer local** (cf. §0-4) | Reséquencer : Mistral local **avant** LLM cloud |
| **4** Tool gateway actions réversibles | le lot « renfort conseillé » | Patron de sûreté **déjà prouvé** (`omni-soar`) | Généraliser, pas reconstruire |
| **5** Console unifiée | Grafana + NestJS | **~80 % déjà là** | Extension ciblée |
| **6** Surface d'attaque | passif + actif | Passif fait ; actif = à déprioriser | Repousser |
| **7** Amélioration continue | revues de posture, registre clause 10 | Rapports + KPI déjà là ; manque le **registre formel** | Valeur réelle = formaliser le registre |
| **8** App iOS | sous-traiter/différer | Dépend d'un workflow d'approbation inexistant ; compétence la moins probable | **Hors périmètre jusqu'à stabilisation** |

---

## 4. Critique des hypothèses (le fond)

**A. Le sophisme du greenfield (critique maîtresse).** Déjà traité §1. Conséquence pratique : toute estimation
en jours-homme du Doc 3 pour les Lots 1-2 est sans objet ; ces lots sont du passé.

**B. Le microservice de corrélation est une réinvention partielle.** `omni-incident-correlate` *est* le
moteur que le Doc 1 veut bâtir. La seule évolution légitime est la **latence** : le corrélateur est un timer
15 min ; les docs suggèrent un flux webhook. Mais c'est « ajouter un déclencheur webhook + un étage LLM au
corrélateur existant », **pas** « construire un nouveau microservice de corrélation ». Deux moteurs = deux
vérités = dérive.

**C. FastAPI est sur-dimensionné pour la forme actuelle.** Tes 26 services sont en **Python stdlib**
(HTTPServer, timers) — choix délibéré, dépendances minimales, idempotents. Les docs imposent par défaut
FastAPI + httpx + APScheduler + pySigma + psycopg/pgvector. Pour un mainteneur **solo** avec le key-person
comme risque #1, empiler un framework async + un ORM + une base vectorielle **contredit** la philosophie qui
fait que ce système est maintenable. Garde le stdlib/systemd pour le service LLM ; n'introduis pgvector que
si le RAG est *validé* nécessaire. **Ne pas importer un framework pour héberger un endpoint.**

**D. Presidio : le bon risque, mais la mauvaise architecture.** Le Doc 3 a raison de marteler le recall FR
modeste (~0,74, téléphones FR à 0 %). Mais il rate une subtilité décisive : **tes données sont en grande
partie structurées** — Graylog te livre `user`, `host`, `src_ip`, `dest_ip`, `process_name`… (schéma connu,
listé dans `CONTEXT.md`). On **n'a pas besoin** de NER probabiliste pour anonymiser un champ connu : on le
**tokenise de façon déterministe** (recall 100 % sur ces champs). Presidio ne sert que pour le **texte libre
résiduel** (lignes de commande, corps de message). Architecture correcte :
*tokenisation déterministe par champ (spine) → Presidio/regex sur le texte libre (backstop) → fail-closed.*
Cela **dé-risque toute la voie LLM cloud** et réduit Presidio d'un point de défaillance à un filet.

**E. La question que les 3 docs n'osent pas poser : « a-t-on besoin de LLM cloud ? »** Ils supposent LLM cloud
désirable et débattent du *comment*. Un regard senior pose le *si*. Le système fait déjà détection + scoring
0-100 + kill-chain. La valeur *marginale* d'un LLM = (1) narratifs pour le RSSI, (2) triage des patterns
nouveaux, (3) brouillon de plan de réponse, (4) revues de posture. Réel, mais c'est un **copilote**. En face :
dépendance ZDR, fuite résiduelle Presidio, surface d'injection (les logs sont *contrôlés par l'attaquant* —
les docs ont raison d'insister), coût (+35 % de tokens au nouveau tokenizer, note Doc 2), maintenance. **Donc :
prouver la valeur en *local* d'abord. Si Mistral 7B suffit au triage, l'épopée LLM cloud/ZDR/Presidio est
peut-être inutile.** Les docs séquencent Mistral→LLM cloud mais n'explicitent jamais ce point de bascule.

**F. Le « ~70 % MXDR » est désormais mesurable — et plus haut que 70 % sur l'axe techno.** Vu l'inventaire,
la reproduction *technique* est plutôt à 75-85 %. L'honnête formulation : **tu as déjà construit l'essentiel
de la *technologie* MXDR ; ce que tu ne peux pas construire, c'est le *service humain 24/7*, la *threat-intel
profonde/dark-web*, et la *garantie cyber* (un produit d'assurance, pas une techno).** Build-vs-buy qui en
découle : n'achète pas un MXDR pour la techno ; envisage un **MDR co-managé uniquement** pour la couverture
nuit/week-end + threat-intel, **si** une analyse de risque le justifie.

**G. Le key-person est bien le risque #1 — et la preuve est accablante.** Cf. §6 : aucun git, aucun test.

**H. Détail de crédibilité technique (les docs « sentent » l'extérieur).** Cf. Annexe. En résumé : l'exemple
curl du Doc 1 tape `:443` alors que l'API est `:9000` derrière nginx, TLS bout-en-bout, `--cacert`,
`X-Requested-By`, et surtout **les helpers `lib-graylog.sh` (wrap_entity/post_entity) existent** ; le bus de
réinjection GELF `:12201` / `event_source=siem_*` **existe** (M365, SOAR, backup, intégrité l'utilisent
déjà) ; et la machine à états du tool gateway **existe en v1** dans `omni-soar`.

**I. Scan actif : prudence juste, mais priorité mal placée.** Tout le laïus « jamais les tunnels partenaires,
masscan proscrit, nmap -T2/-T3, systemd timers » est correct. Mais le passif + la détection de scan + le KEV
existent déjà. Le scan actif est **la brique la plus risquée et la moins différenciante** — à repousser, et
seulement en OpenVAS authentifié *minimally invasive* si l'auditeur A.8.8 en demande plus.

**J. Console : les docs sur-construisent.** Dashboard SOC 19-21 pages + carte temps réel = le « single pane »
est là. Les vrais manques sont étroits : surface d'**approbation** (utile seulement avec les actionneurs (2))
et **auth nominative** (LDAPS existe, mais compte `admin` partagé encore utilisé). iOS = différer/sous-traiter.

---

## 5. Ce que les docs ont juste (à conserver tel quel)

- **Injection de prompt = risque #1, défense *architecturale* et non *modèle*** : politique d'autorisation
  jamais déléguée au LLM, exécution déterministe côté orchestrateur, human-in-the-loop pour le non-réversible.
  Aligné ANSSI R9/R25/R27. **Garder intégralement.**
- **Recall Presidio à mesurer sur corpus réel** (je ne fais qu'inverser spine/backstop, pas annuler la garde).
- **ZDR n'est pas self-service** (accord Sales/Enterprise, exclusions modèles Mythos/Fable, classifieurs de
  sûreté retenus) — caveat correct si la voie LLM cloud est engagée.
- **« Read-only / advisory d'abord, puis actions »** — correct et conforme à ta culture prudente existante.
- **Mapping ISO** (A.8.11 masquage, A.5.34 PII, clause 10) — correct.
- **Build-vs-buy par composant** : construire le cœur différenciant, adopter l'OSS (SigmaHQ, Presidio).
- **Note calendrier RC4/Kerberos 2026** (CVE-2026-20833, enforcement avril 2026, fin du rollback juillet) :
  **utile et actionnable maintenant** — ta détection Kerberoasting va voir sa base de faux positifs RC4 fondre ;
  ajoute la surveillance de l'**AES anormal (0x12)** et des **pics 4769 par compte (règle 3-sigma)**. À porter
  dans `12-graylog-pipelines.sh` / `omni-ueba-*` indépendamment de tout le reste.

---

## 6. Risques, réordonnés (vérifiés sur le système réel)

1. **🔴 Key-person / absence de contrôle de version — CRITIQUE, IMMÉDIAT.**
   `git` n'est **pas installé** ; **aucun dépôt** sous `/root`. **10 238 lignes** de bash de prod (59 scripts)
   + **26 microservices Python** ne sont **sous aucun versioning**. Aucun test, aucune CI, aucun shellcheck.
   Seul filet : le tar AES-256 quotidien vers SMB. Le savoir d'exploitation vit dans `CONTEXT.md` (un
   changelog) **et dans ta tête**. Si tu pars demain, c'est une boîte noire. *Note ISO : c'est aussi un trou
   de maîtrise du changement (A.8.32) et de la clause 10.* **→ Action P0, avant toute IA (cf. §7).**
2. **🟠 Injection de prompt indirecte** (dès qu'un LLM lit des logs). Traité par l'architecture (politique
   déterministe + human-in-loop). **Ne jamais** donner au LLM une action destructive en auto.
3. **🟠 Secrets en clair.** Les secrets de service vivent dans `00-vars.env` (chmod 600, **plaintext**).
   Vaultwarden est aujourd'hui une *source de logs auditée*, **pas** un backend de récupération de secrets.
   Or le service de réponse détiendra les creds les plus puissants (isolate ESET, disable AD) : **ceux-là
   surtout** ne doivent pas finir en clair dans `00-vars.env`. *La « récupération de secrets via Vaultwarden »
   des docs est donc à la fois du net-new ET un vrai durcissement à faire.*
4. **🟠 Scan actif sur prod + tunnels partenaires** — risque réel mais **évitable en repoussant la brique**.
5. **🟡 Fatigue d'alerte / d'approbation** — déjà rencontrée (tempête « Force brute » du 12/06). Le LLM peut
   *aider* (regrouper, narrer) ou *aggraver* (une approbation de plus). À surveiller.
6. **🟡 Divergence de moteurs** si on construit une 2ᵉ corrélation à côté de `omni-incident-correlate`.

---

## 7. Décision : séquence révisée + build-vs-buy

**Principe directeur :** greffer une fine couche IA sur un socle qui marche, en commençant par dé-risquer
l'organisationnel et le local avant l'externe et le contractuel.

**P0 — Mettre l'existant sous git + filet de test (3-5 j). NON NÉGOCIABLE, AVANT TOUT.**
Installer git, initialiser le dépôt (monorepo : scripts + `windows/` + `fortigate/` + `lookups/` + `docs/` +
**copie versionnée des `/usr/local/sbin/omni-*`**), pousser sur le serveur GIT interne déjà sauvegardé.
Ajouter : `shellcheck` sur les `.sh`, un smoke-test de syntaxe (`bash -n`) + un test de migration idempotente,
externaliser le runbook hors de ta tête. *Sert directement A.8.32 / clause 10 pour l'audit.* **Aucune ligne
d'IA avant ce point.**

**P1 — Triage LLM *local* en mode advisory (≈8-12 j).**
27ᵉ microservice `omni-llm-triage` (stdlib, timer ou webhook) : consomme `event_source=incident` (score ≥ seuil)
→ prompt Mistral/Ollama local → émet `event_source=llm_triage` en GELF (narratif + technique + plan proposé)
→ page dashboard + mail. **Zéro LLM cloud, zéro Presidio, zéro ZDR.** *Teste l'hypothèse centrale* : le LLM
ajoute-t-il de la valeur au-dessus du score 0-100 ? Si non, tu as économisé tout le programme LLM cloud.

**P2 — Généraliser `omni-soar` en tool-gateway (≈10-15 j), actions réversibles uniquement.**
Étendre la machine à états existante (validate→politique→TTL→exécute→audit) à : **isolation ESET** (API ESET
PROTECT — net-new), **désactivation AD** (compte dédié moindre privilège). Réversible + rollback + dry-run par
défaut + exclusion stricte des 14 tunnels partenaires. Surface d'approbation = la seule vraie extension console.
Secrets de réponse → durcir (cf. §6-3).

**P3 *(conditionnel)* — Chaîne LLM cloud (≈15-25 j), si et seulement si P1 prouve la valeur ET un cas réel échappe
à Mistral 7B.** Tokenisation **déterministe** sur le schéma connu (spine) + Presidio backstop sur texte libre +
fail-closed + accord ZDR + DPA. Routeur Mistral/LLM cloud par score. **Fail-safe : si anonymisation douteuse ou
ZDR non confirmé → reste local.**

**P4 *(optionnel / repoussé)* — Surface active (OpenVAS authentifié si A.8.8 l'exige), Grafana infra, registre
clause 10 formalisé. iOS : hors périmètre jusqu'à stabilisation complète.**

**Build-vs-buy :**
- **Construire** : le service LLM, l'extension tool-gateway, la surface d'approbation (cœur différenciant).
- **Adopter (OSS)** : règles SigmaHQ, Presidio (backstop only), OpenVAS (si besoin A.8.8).
- **Acheter / envisager** : MDR co-managé **uniquement** pour le 24/7 humain + threat-intel/dark-web (les gaps
  *irréductibles*), pas pour la techno. **Sous-traiter** : iOS, polish UI.
- **Ne pas construire** : 2ᵉ moteur de corrélation, FastAPI pour un endpoint, orchestration lourde n8n.

---

## 8. Décisions ouvertes (à trancher par Julien)

1. **Périmètre LLM cloud :** acceptes-tu le principe « local d'abord, LLM cloud seulement si prouvé nécessaire »,
   ou y a-t-il un impératif (client, direction) à intégrer LLM cloud d'emblée ?
2. **ZDR / souveraineté :** es-tu prêt à engager un accord ZDR + DPA fournisseur LLM (négociation Sales), ou la
   contrainte RGPD/souveraineté impose-t-elle de rester 100 % local pour les données d'alerte ?
3. **Actionneurs de réponse :** jusqu'où en auto ? (proposition : isolation ESET + désactivation AD en
   *réversible auto* avec rollback ; tout le reste en human-in-the-loop — comme `omni-soar` aujourd'hui).
4. **Scan actif :** l'auditeur A.8.8 se contente-t-il du KEV/patch-age + passif (alors on repousse l'actif),
   ou exige-t-il un scan de vulnérabilité actif (alors OpenVAS authentifié, scope OMNITECH strict) ?
5. **MDR co-managé :** veux-tu que je chiffre l'option « nuit/week-end + threat-intel externalisés » comme
   complément, ou le 24/7 humain reste-t-il hors budget (et donc gap assumé) ?
6. **Priorité immédiate :** confirmes-tu P0 (git/tests) avant toute IA ? C'est ma recommandation forte.

---

## Annexe — Corrections techniques de crédibilité (pour tout futur code IA)

- **API Graylog :** pas `:443` mais **`https://${SIEM_FQDN}:9000/api`**, TLS bout-en-bout, `--cacert
  /etc/graylog/certs/omnitech-rootca.crt`, en-tête `X-Requested-By` sur tout non-GET. **Réutiliser
  `lib-graylog.sh`** (`api_get`/`api_put`/`wrap_entity`/`post_entity`) — l'enveloppe `CreateEntityRequest`
  (`{"entity":…, "share_request":…}`) est déjà gérée, et `api_put` peut renvoyer exit 0 sur échec → **toujours
  vérifier `.id`** (piège documenté CONTEXT §7octies).
- **Bus de réinjection :** GELF `:12201`, `event_source=siem_*` / `*_score` / `incident` / `llm_triage`,
  routés vers le stream **« OMNI - Interne SIEM »**. Les verdicts LLM doivent rouler sur **ce** bus existant,
  pas un nouveau. (Rappels GELF : JSON 1 ligne, champs custom préfixés `_`, IP au format `ip` sans `:port` —
  `clean_ip()` existe déjà ; booléens ignorés à l'ingestion.)
- **Machine à états :** `omni-soar` implémente déjà valider→politique(non-RFC1918/whitelist/seuil)→cap/TTL→
  exécuter→audit GELF. La généralisation du tool-gateway part de **là**.
- **Secrets :** aujourd'hui `00-vars.env` (plaintext, 600). Vaultwarden = source de logs, **pas** backend de
  secrets. La « récupération via API Vaultwarden » des docs = net-new + durcissement (prioritaire pour les
  creds de réponse).
- **Idiome :** services en **Python stdlib + systemd timers**, scripts **idempotents**. Tout nouveau service IA
  doit suivre ce moule (testable, sans framework lourd, key-person-friendly).

---
*Document de revue — à verser au dossier de décision (REG_016) et à relier au registre d'amélioration continue
(clause 10) une fois les décisions §8 tranchées.*
