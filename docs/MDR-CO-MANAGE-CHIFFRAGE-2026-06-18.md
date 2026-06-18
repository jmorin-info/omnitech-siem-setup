# MDR co-managé — chiffrage & décision (couverture nuit/week-end + threat-intel)

**OMNITECH SECURITY — 2026-06-18 — destiné à : Julien Morin (RSSI/dev)**
**Décision amont :** retenir un **MDR co-managé** pour combler les 3 gaps *irréductibles* du build interne
(SOC humain 24/7, threat-intel/dark-web, garantie cyber). Voir `docs/REVUE-CRITIQUE-PLATEFORME-IA-2026-06-18.md`.
**Portée de ce doc :** cadrer le périmètre, le modèle, comparer le marché 2026, chiffrer, et lister les
critères de bascule + questions d'appel d'offres.

> ⚠️ **Fiabilité des chiffres.** Les prix MDR sont quasi tous **sur devis** ; les fourchettes ci-dessous
> proviennent de benchmarks publics 2026 (sources en fin de doc) et d'**estimations explicitement signalées
> `[EST]`**. Aucun n'est un devis OMNITECH. Taux retenu : 1 USD ≈ 0,93 €.

---

## TL;DR

- **Le périmètre rationnel n'est PAS un MDR full-stack** (qui doublonnerait ton SIEM/EDR déjà mûrs) mais une
  **augmentation de SOC co-managée** : couverture **nuit + week-end + jours fériés**, l'équipe interne gardant
  la main en journée ouvrée et **restant propriétaire de la politique de détection**, + un volet
  **CTI/dark-web**.
- **Choisir un prestataire *technology-agnostic* (BYO-SIEM/EDR)** qui consomme tes alertes Graylog et ta
  télémétrie ESET **par API**, surtout pas un MDR « plateforme-native » qui impose son agent. **Conséquence
  contre-intuitive : Bitdefender MDR — la référence que tu voulais reproduire — est éliminé** (agent
  GravityZone obligatoire, pas d'EDR tiers, SOC hors UE).
- **Privilégier un acteur souverain FR/UE** (Orange Cyberdefense SecNumCloud, Advens, Intrinsec, Sekoia) —
  cohérent avec ton choix « local d'abord » pour le LLM et avec la sous-traitance ISO (A.5.19–A.5.23).
- **Chiffrage de planification** : option ciblée nuit/WE co-managée ≈ **35 000 – 80 000 €/an** `[EST]` ;
  + CTI/dark-web ≈ **10 000 – 40 000 €/an** `[EST]`. À comparer à un MDR **full 24/7** ≈ **60 000 – 140 000 €/an**
  `[EST]` et à un **24/7 interne réel** (~5-6 ETP) ≈ **400 000 – 550 000 €/an** `[EST]`.
- **Verdict : le co-managé nuit/WE est économiquement rationnel** (un ordre de grandeur sous le 24/7 interne,
  plus soutenable qu'une astreinte maison). **Mais n'attends PAS un rabais proportionnel** « parce qu'on ne
  prend que les nuits » : le SOC du prestataire tourne 24/7 de toute façon, l'onboarding et la télémétrie sont
  complets — négocie un *palier co-managé/augmentation* explicite.

---

## 1. Périmètre retenu

**Ce qu'on achète :**
- **Couverture temporelle** : nuits (≈ 19h–8h), week-ends, jours fériés — soit les ~128 h/semaine où l'équipe
  interne n'est pas opérationnelle (sur 168 h). Surveillance, triage, et **réponse de 1er niveau** (selon
  mandat) sur les alertes critiques.
- **Threat-intel / dark-web monitoring** : veille sur fuites de credentials OMNITECH, exposition de domaines/
  marques, mentions sur forums/markets, IOC contextualisés réinjectables dans Graylog/SOAR.
- **Astreinte d'escalade** : un contact joignable < 30 min sur incident critique nocturne (équivalent maison
  des « Pre-Approved Actions » + SAM de Bitdefender).

**Ce qu'on n'achète PAS** (déjà couvert par le build interne, cf. revue) :
- Le moteur de détection (pipelines Graylog, 74 règles MITRE, UEBA/NDR, corrélation d'incidents).
- Le SOAR de blocage FortiGate (`omni-soar`), le reporting, les dashboards SOC.
- L'EDR (ESET) — conservé comme source de télémétrie ; on ne remplace pas l'agent.

**Principe directeur (co-managé, pas externalisé) :** OMNITECH **reste propriétaire** de la politique de
détection et de la décision d'action ; le prestataire **opère les heures creuses** et **enrichit** (CTI),
sans imposer son stack ni reprendre la gouvernance. Modèle « your internal security team remains the primary
owner of your policy configuration » (formulation co-managée standard du marché).

---

## 2. Modèle co-managé : RACI, articulation technique, réversibilité

**RACI synthétique :**

| Activité | Interne (jour ouvré) | Prestataire (nuit/WE) |
|---|---|---|
| Politique & règles de détection | **R/A** (propriétaire) | C (propose des améliorations) |
| Tuning, exceptions, allowlists | **R/A** | C |
| Triage des alertes (heures ouvrées) | **R/A** | I |
| Triage + investigation (nuit/WE) | I | **R** (A reste interne) |
| Réponse réversible (isolation/blocage) | **R/A** | **R** sur actions pré-approuvées, sinon escalade |
| Threat-intel / dark-web | C | **R/A** |
| Décision d'action destructrice | **A** (human-in-the-loop interne) | escalade obligatoire |
| Conformité ISO / preuves | **R/A** | C (fournit logs d'intervention) |

**Articulation avec le SIEM/EDR existants — le critère technique n°1 :**
- **Modèle souhaité (BYO)** : le prestataire **consomme** tes flux — alertes/événements Graylog (API REST,
  webhook, ou export Syslog/CEF) + télémétrie ESET — et travaille **dans** ta console ou sa surcouche
  (type ReliaQuest GreyMatter / Binary Defense), **sans réingestion forcée** dans son propre SIEM.
- **Modèle à éviter** : le MDR plateforme-native qui exige **son** agent (Bitdefender = GravityZone
  obligatoire, pas d'EDR tiers) → re-déploiement parc, double agent, perte de la valeur du build, lock-in.
- **Point de coût caché** : si le prestataire **réingère** tes logs dans son SIEM, la facturation **au volume**
  s'applique (≈ 0,50–2,00 $/Go au-delà d'un socle). Or tu produis **~25 Go/jour (~750 Go/mois)** → à cadrer
  impérativement (filtrer ce qui part, ou rester en modèle « le presta lit Graylog »).

**Réversibilité (exigence contractuelle) :** données et règles restent chez toi (Graylog est le point de
vérité) ; clause de sortie avec restitution/destruction des données, pas de dépendance à un agent propriétaire,
préavis raisonnable. C'est précisément l'avantage du co-managé BYO sur le MDR plateforme.

---

## 3. Options marché (2026)

| Fournisseur | Tarification (indicative) | Co-managé réel / BYO-SIEM-EDR | Intégration stack tiers (Graylog/ESET) | Localisation données |
|---|---|---|---|---|
| **Bitdefender MDR / MDR PLUS** | Sur devis ; 2 paliers. MTTD 24 min (MITRE 2024), SLA notif ≤30 min. Garantie jusqu'à **1 M$ mais ≥1000 endpoints** (→ **OMNITECH non éligible**) | ❌ « Co-Managed » marketing mais **agent GravityZone obligatoire, pas d'EDR tiers** | ❌ Faible (impose son agent) | ❌ SOC San Antonio / Bucarest / Singapour — **pas de garantie résidence UE** |
| **Arctic Wolf MDR** | $8–25/endpoint/mois (base) ; SMB effectif $25–40/user/mois ; entrée ~44 k$/an (≤100 users), deal médian ~96 k$/an | ◐ Concierge Security Team, modèle « tes outils + notre SOC » | ◐ Connecteurs SIEM/EDR larges | ❌/◐ US-centric (option UE à vérifier) |
| **Sophos MDR** | $7–17/endpoint/mois (base) ; effectif $15–25/user/mois avec serveurs + Intercept X + packs | ◐ Supporte télémétrie tierce (« MDR Complete ») mais pousse son EDR | ◐ Intègre EDR/SIEM tiers via packs | ◐ Région UE disponible (à confirmer) |
| **Orange Cyberdefense** (FR) | Sur devis | ✅ SOC managé / MDR / XDR, modèle co-managé | ✅ Agnostique, fort en intégration | ✅ **SecNumCloud** (Cloud Avenue SecNum qualifié ANSSI, juil. 2025) |
| **Advens / ITrust** (FR) | Sur devis | ✅ Acteurs revendiquant l'**autonomie stratégique** totale | ✅ Agnostique | ✅ FR souverain |
| **Intrinsec** (FR) | Sur devis | ✅ **SOC externalisé 24/7**, experts certifiés ANSSI, SIEM/SOAR | ✅ Agnostique (CTI réputée) | ✅ FR |
| **Sekoia.io** (FR/UE) | Sur devis (plateforme + MDR partenaires) | ✅ Plateforme SOC/XDR ouverte, 900+ règles, 24/7 | ✅ **Conçue pour ingérer des sources tierces** | ✅ UE |
| **ReliaQuest / Binary Defense / Huntress** (US) | Sur devis | ✅ **BYO-SIEM/EDR** explicite (surcouche au-dessus de l'existant) | ✅ API-first, portabilité des données | ❌ US (sauf option UE) |

**Lecture :** pour OMNITECH (souveraineté + conserver Graylog/ESET), le **quadrant gagnant = acteurs FR/UE
agnostiques** (Orange Cyberdefense, Advens, Intrinsec, Sekoia). Les BYO US (ReliaQuest/Binary Defense) sont
techniquement excellents mais perdent sur la souveraineté. Bitdefender est **disqualifié** par le lock-in agent
et la localisation — paradoxe assumé : on reproduit sa *techno* en interne, on ne prend pas son *service*.

---

## 4. Chiffrage

**Base de dimensionnement OMNITECH :** ~**150 postes** + ~**90 VMs/serveurs** + 3 sites. Multiplicateur serveur
courant **1,5–2,5×** le tarif poste (les serveurs tournent 24/7, génèrent plus de télémétrie). « Endpoint-
équivalents » ≈ 150 + (90 × ~2) ≈ **~330**.

| Scénario | Hypothèses | Coût annuel `[EST]` |
|---|---|---|
| **A. MDR full 24/7** (référence haute) | 150 postes @ 10–25 $/mois + 90 serveurs @ 50–100 $/mois | **~60 000 – 140 000 €/an** |
| **B. Co-managé ciblé nuit/WE + escalade** (option retenue) | ~40–70 % d'un full (le SOC tourne 24/7, onboarding complet ; pas de rabais proportionnel) | **~35 000 – 80 000 €/an** |
| **C. CTI / dark-web** (autonome ou bundle) | brand/credential/domain monitoring → CTI complète | **~10 000 – 40 000 €/an** |
| **B + C combinés** (cible OMNITECH) | souvent bundle partiel chez les FR | **~45 000 – 100 000 €/an** |
| **D. 24/7 interne réel** (anti-modèle) | 5–6 ETP analystes SOC, coût chargé ~80–110 k€/ETP | **~400 000 – 550 000 €/an** |
| **E. Astreinte interne légère** (compromis bancal) | 3–4 pers. en rotation + primes d'astreinte | **~60 000 – 120 000 €/an** mais réponse dégradée + risque burnout/key-person |

**Pièges de facturation à neutraliser en RFP :**
1. **Volume de logs** : ~750 Go/mois — exiger un modèle « lecture de Graylog » ou un socle Go inclus généreux,
   sinon surfacturation 0,50–2,00 $/Go.
2. **Serveurs** : 90 VMs au multiplicateur 2–2,5× peuvent **doubler** la facture vs un comptage « par poste ».
3. **Add-ons** : rétention >90 j, awareness, IR retainer, onboarding → vérifier ce qui est inclus.
4. **Engagement** : remises 1 an vs 3 ans (attention à la réversibilité si lock-in).

---

## 5. Build-only vs co-managé : ce que le co-managé ajoute *réellement*

Le build interne couvre déjà **75–85 % de la techno** MXDR (cf. revue). Le co-managé n'ajoute pas de techno —
il ajoute **3 choses non-reproductibles en interne à coût raisonnable** :

1. **Des yeux humains la nuit/WE.** L'alternative (scénario D) coûte **5–10×** plus cher pour un vrai 24/7
   staffé ; l'astreinte légère (E) est moins chère mais **dégradée** (latence, fatigue, et surtout
   **aggrave le risque key-person** — l'inverse de ce qu'on vient de corriger avec le P0 git).
2. **Threat-intel/dark-web** que tu ne peux pas produire seul (pas de Bitdefender Labs / pas d'équipe CTI).
3. **Un transfert de risque** (et, chez certains, une garantie cyber — mais réservée aux gros parcs ;
   OMNITECH à 150 postes n'atteint pas les seuils des garanties 1 M$).

**Coût d'opportunité :** chaque euro mis dans un MDR *full-stack* qui doublonne Graylog/ESET est gaspillé.
La dépense n'est justifiée **que** sur le delta (nuit/WE + CTI). D'où le périmètre §1.

---

## 6. Conformité & souveraineté

- **RGPD / localisation** : les logs contiennent des données personnelles (logins, IP, UPN M365). Exiger
  **traitement et stockage en UE**, DPA signé, liste des sous-traitants ultérieurs, pas de transfert hors UE
  sans garanties. → favorise nettement les acteurs **FR/UE** ; **disqualifie** un SOC US/hors-UE sans option
  de résidence (Bitdefender tel quel).
- **SecNumCloud / ANSSI** : si l'analyse de risque l'exige (ou exigence client/assurance), viser un hébergement
  **SecNumCloud** (Orange Cloud Avenue SecNum qualifié juil. 2025) — « impermeabilité aux lois extra-UE ».
- **ISO 27001:2022 — sous-traitance** : la mission relève de **A.5.19–A.5.23** (relations fournisseurs,
  sécurité dans les accords, gestion de la chaîne d'appro, surveillance des services fournisseurs, sécurité
  cloud). Pour l'**audit Stage 2 (nov. 2026)** : contrat + DPA + SLA + clauses de réversibilité + **revue
  périodique du prestataire** (preuve attendue). Le co-managé bien tracé devient une **preuve** de A.5.7
  (threat-intel) et A.8.16 (surveillance 24/7), pas un trou.
- **Clauses contractuelles clés** : SLA de notification (< 30 min critique), périmètre exact des actions
  autorisées la nuit (réversibles uniquement, escalade pour le destructif — aligné ANSSI R9), propriété et
  **réversibilité des données/règles**, droit d'audit, localisation, sous-traitants, plan de sortie.

---

## 7. Recommandation, critères de bascule, questions RFP

**Recommandation :**
1. Lancer un **RFP restreint** auprès de **3–4 acteurs FR/UE agnostiques** : **Orange Cyberdefense, Advens,
   Intrinsec, Sekoia** (+ éventuellement un BYO US comme étalon de prix : ReliaQuest/Binary Defense).
2. Périmètre RFP = **co-managé nuit/WE + CTI/dark-web** (scénario B+C), **BYO-SIEM/EDR** (lecture de Graylog +
   ESET, pas de réingestion forcée), réversibilité forte.
3. Budget de cadrage : **~45 000 – 100 000 €/an** `[EST]`, à confirmer par devis. Exclure d'emblée le MDR
   full-stack et tout fournisseur exigeant son agent.

**Critères de déclenchement (quand signer) :**
- Incident(s) nocturne(s)/week-end **détecté(s) trop tard** dans l'exploitation réelle (mesure MTTD hors heures
  ouvrées) ; **ou**
- Exigence **client/assurance/audit** d'un SOC 24/7 ; **ou**
- Impossibilité RH d'assurer une astreinte interne soutenable (le scénario E confirmé intenable).
*À défaut, rester en build-only + alerting (l'amélioration des notifications réduit déjà le risque de rater un
signal) et réévaluer après 6 mois d'exploitation.*

**Questions ouvertes pour l'appel d'offres :**
- Consommez-vous **nos** alertes Graylog / notre EDR ESET **par API**, ou imposez-vous votre stack/agent ?
- Tarification **exacte** : par poste, par serveur (multiplicateur ?), au volume de logs (socle Go inclus ?) ?
- Modèle **nuit/WE** : palier dédié, ou prix d'un 24/7 plein ? Remise réelle pour couverture partielle ?
- **Localisation** des données et des analystes ? SecNumCloud disponible ?
- Périmètre des **actions autonomes** la nuit ? Process d'escalade < 30 min ?
- **CTI/dark-web** : inclus ou option ? Quelles sources, quel reporting réinjectable dans Graylog/SOAR ?
- **Réversibilité** : restitution/destruction des données, préavis, plan de sortie ?

---

## Caveats

- **Aucun prix ici n'est un devis OMNITECH.** Les `[EST]` sont des fourchettes de planification dérivées de
  benchmarks publics 2026 et d'hypothèses de dimensionnement (multiplicateur serveur, volume de logs) ; l'écart
  réel peut être large. **Sortir 2–3 devis avant tout budget engagé.**
- Les **prix FR/UE sont opaques** (devis only) : la comparaison souveraine se fait sur le modèle et la
  conformité, pas (encore) sur le prix affiché.
- La **garantie cyber** (1 M$ Bitdefender) ne s'applique qu'aux gros parcs (≥1000 endpoints) — **non
  pertinente** pour OMNITECH ; le transfert de risque passe plutôt par une **assurance cyber** classique.
- Le marché MDR évolue vite (consolidation, BYO en hausse) : revérifier offres/résidence au moment du RFP.

## Sources
- [MDR Cost 2026 (mdrcost.com)](https://mdrcost.com/) · [MDR Providers — pricing](https://mdrproviders.io/pricing) · [MDR pricing 2026 (learn)](https://mdrproviders.io/learn/mdr-pricing)
- [Bitdefender MDR review 2026 (mdrproviders.io)](https://mdrproviders.io/providers/bitdefender-mdr) · [Bitdefender Managed Services](https://www.bitdefender.com/en-us/business/services/managed-services)
- [Arctic Wolf MDR](https://arcticwolf.com/solutions/managed-detection-and-response/) · [Sophos MDR review 2026 (zerometric)](https://zerometric.net/review/sophos-mdr/) · [UnderDefense — MDR pricing](https://underdefense.com/mdr-pricing/)
- [Co-managed security services (SonicWall)](https://www.sonicwall.com/glossary/comanaged-security-services) · [Huntress — MDR/EDR vendors 2026](https://www.huntress.com/cybersecurity-insights/managed-detection-response-vendors)
- [MSSP souverains (Journal du Net)](https://www.journaldunet.com/cybersecurite/1541445-mssp-souverains-qui-sont-ils/) · [SOC managés France 2026 (SOC Monitor)](https://soc-monitor.com/acteurs/soc-manages-france/) · [Intrinsec — SOC 24/7](https://www.intrinsec.com/en/soc-securite-operationnelle/) · [Sekoia.io](https://www.sekoia.io/en/homepage/) · [Orange — souveraineté/SecNumCloud](https://www.orange.com/en/whats-up/european-digital-sovereignty-orange-steps-face-growing-threats)

---
*Document de chiffrage/décision — à verser au dossier (REG_016) et à lier au registre des fournisseurs /
analyse de risque pour l'audit ISO 27001 Stage 2 (nov. 2026).*
