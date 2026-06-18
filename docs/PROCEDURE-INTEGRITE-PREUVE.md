# Intégrité & valeur probante des journaux — OMNITECH SIEM

> ISO/IEC 27001 : A.8.15 (journalisation + **protection des journaux**), A.8.2 (droits d'accès privilégiés), A.5.28 (collecte de preuves). · 2026-06-14

## Problème adressé
Graylog OSS n'a pas d'archivage natif (Enterprise) et un administrateur peut supprimer/altérer des index (démontré : purge de 22,9 M docs). Sans contrôle, les journaux n'ont pas de **valeur probante**. On met en place une **preuve d'inaltérabilité (tamper-evidence)** OSS + du **moindre privilège**.

## Dispositif en place

### 1. Registre d'intégrité haché-en-chaîne + signé (`60-integrity.sh` → `/usr/local/sbin/omni-integrity`)
- **Quotidien (03:30)** : un *maillon* capture l'état du corpus (par index : `docs`, `bytes`, `uuid` ; totaux). Chaque maillon inclut le **hash SHA-256 du maillon précédent** (chaînage) et est **signé HMAC-SHA256** avec une clé root-only (`/etc/graylog/omni-integrity.key`, chmod 600).
- **Hors-SIEM** : le registre `/var/lib/omni-integrity/chain.jsonl` est copié à chaque exécution vers `//10.33.50.5/Public/SIEM/integrity/` → un insider du SIEM **ne peut pas réécrire l'historique** (la copie hors-bande + la signature le trahiraient).
- **Attestation** : chaque exécution émet un événement `event_source:siem_integrity` dans le SIEM lui-même (le SIEM atteste de son propre état).
- **Vérification à tout moment** : `omni-integrity --verify` → recalcule tous les hash, vérifie la signature HMAC et le chaînage. *Toute* altération (suppression masquée, édition) **casse la chaîne** (testé : falsifier une valeur ⇒ « CHAINE COMPROMISE »).

**En cas d'enquête / audit** : exécuter `omni-integrity --verify`, puis comparer `chain.jsonl` (SIEM) avec la copie SMB hors-bande (doivent être identiques jusqu'au dernier maillon commun). Une divergence ou une chaîne rompue = manipulation à investiguer.

### 2. Moindre privilège (anti-tampering préventif) — ISO A.8.2
- Rôle Graylog **« OMNI - Analyste (lecture seule) »** créé : lecture flux/recherches/dashboards, **aucun droit d'admin ni de suppression**.
- **Politique** : les comptes SOC utilisent ce rôle. Le compte **admin** (seul à pouvoir supprimer index/streams) est **break-glass** : usage exceptionnel, traçé (accès au SIEM journalisé), MDP au coffre, idéalement MFA.

### 3. Sauvegarde de configuration chiffrée hors-bande (`30-backup-config.sh`)
- Archive **AES-256** de la config (sans les logs) poussée quotidiennement vers le partage SMB, rétention bornée. Garantit la reconstruction (cf. `PRA-RECONSTRUCTION-SIEM.md`).

## Procédure d'extraction de preuve (chaîne de possession)
Pour produire des logs à valeur probante (incident, réquisition) :
1. Délimiter la recherche (Graylog ou OpenSearch) : période + critères, **horodatage UTC**.
2. Exporter le résultat (CSV/JSON).
3. **Sceller** : `sha256sum export.json > export.json.sha256` + noter date/heure, opérateur, motif.
4. Joindre l'extrait du registre d'intégrité (`omni-integrity --verify` + le maillon couvrant la période) qui atteste que le corpus n'a pas été altéré sur l'intervalle.
5. Conserver l'ensemble (export + hash + attestation) sur support maîtrisé ; journaliser la remise (qui/quand/à qui).

## Limites & évolution
- Le registre prouve l'inaltérabilité de l'**état** du corpus (suppression/altération **détectable**), pas une immutabilité du **contenu** au niveau bit. Pour aller plus loin : expédier les logs vers un stockage **WORM / S3 Object Lock** (immuable côté stockage) — chantier infra à part.
- Entra ID **P1** actuel : passer en **P2** enrichit la détection cloud (niveaux de risque, riskyUsers) — cf. couverture M365.

## Contrôles périodiques (à inscrire au plan d'exploitation)
- **Hebdo** : `omni-integrity --verify` (et comparaison avec la copie SMB).
- **Mensuel** : revue des comptes Graylog (qui a l'admin ?) + rotation de la clé HMAC si compromission suspectée.
