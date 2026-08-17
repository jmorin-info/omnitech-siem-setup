# Ajouter le 2e SEAL — BX-SEAL-OMEGA (10.33.140.1) — PRODUCTION

Onboarding d'un second SEAL en multi-site. Le site est distingué par le champ
`seal_site` (`bx-qa-seal-vm` pour l'actuel, `bx-seal-omega` pour ce serveur).
Les streams, pipelines, dashboards et détections SEAL existants couvrent les
DEUX sites sans modification. QA → PROD : précautions renforcées ci-dessous.

Faits vérifiés : `10.33.140.1:1433` ouvert depuis le SIEM ; hôte =
`BX-SEAL-OMEGA.omnitech.security` ; CA racine OMNITECH déjà dans le truststore.

---

## 0. PRODUCTION — précautions (lire avant de commencer)

- **Collecte = lecture seule** (compte de service sur des vues) : faible risque.
- **Le point sensible = l'ajout du rowversion sur `dbo.EVENEMENTS`** (watermark) :
  `ALTER TABLE ADD <rowversion>` **réécrit toute la table**. Sur un EVENEMENTS de
  prod (potentiellement plusieurs millions de lignes) → **fenêtre de maintenance
  + accord RSSI**. Deux options :
  - **Option A (recommandée si la fenêtre est possible)** : appliquer le DDL tel
    quel (comme la QA). `ALARMES.VERSION` est déjà un rowversion natif (aucun
    ALTER) ; les 15 tables `Audit.*` sont petites (ALTER instantané) ; seul
    `EVENEMENTS` demande la fenêtre.
  - **Option B (sans réécriture de table)** : ne PAS ajouter de rowversion sur
    EVENEMENTS ; utiliser `EVEN_STORAGE_TIMESTAMP` (NOT NULL, horodatage serveur)
    comme watermark. Nécessite une variante de la vue `vw_SealEvents_SIEM`
    exposant `EVEN_STORAGE_TIMESTAMP AS WatermarkTs` et un input Logstash en
    `tracking_column_type => "timestamp"` (au lieu de numeric) avec un léger
    recouvrement (`>=` + dédup) car un datetime n'est pas strictement monotone.
    Me le demander pour générer la variante si vous choisissez B.
- **Ne PAS exécuter `inject_synthetic.sql` / `cleanup.sql` sur la prod** (QA
  uniquement ; garde-fou `BX-QA-SEAL%` les bloque de toute façon).

## 1. Sur BX-SEAL-OMEGA (SQL, admin) — DDL

Même package que la QA (`1-sql-sur-SEAL/`). Le compte de service est **dédié à ce
serveur** (identifiants distincts) :

```sql
CREATE LOGIN [svc_graylog_seal] WITH PASSWORD = '<mot de passe fort DEDIE omega>', CHECK_POLICY = ON;
USE [SEAL]; CREATE USER [svc_graylog_seal] FOR LOGIN [svc_graylog_seal];
```

Puis (fenêtre de maintenance pour l'étape 01) :
```powershell
powershell -ExecutionPolicy Bypass -File .\Run-SealDDL.ps1 -SqlUser sa
```
Le DDL n'a pas de garde-fou machine (il cible `-d SEAL` sur le serveur courant) :
rien à lever pour le DDL. Vérifier en fin de run : 5 vues créées, compte verrouillé.

## 2. Sur le SIEM — keystore (identifiants OMEGA)

```bash
KS=/usr/share/logstash/bin/logstash-keystore
KP=$(grep -oP 'LOGSTASH_KEYSTORE_PASS=\K.*' /etc/logstash/keystore.env)
printf '%s' 'svc_graylog_seal'        | LOGSTASH_KEYSTORE_PASS="$KP" $KS --path.settings /etc/logstash add SEAL2_DB_SVC_USER --stdin
printf '%s' '<mdp svc omega (Vault)>' | LOGSTASH_KEYSTORE_PASS="$KP" $KS --path.settings /etc/logstash add SEAL2_DB_SVC_PWD  --stdin
```

## 3. Sur le SIEM — déployer les inputs OMEGA

```bash
sudo install -m0640 -o root -g logstash seal/logstash/seal-omega.conf /etc/logstash/conf.d/seal-omega.conf
# amorcer les watermarks (choisir) :
#   - pas de backfill (recommande en prod au demarrage) : valeur courante
#     @@DBTS de BX-SEAL-OMEGA (SELECT CONVERT(BIGINT,@@DBTS) sur ce serveur)
#   - backfill complet : '--- 0'
for f in events alarms audit; do printf -- '--- <SEED>\n' > /var/lib/logstash/seal/.omega_${f}_last_run; \
  chown logstash:logstash /var/lib/logstash/seal/.omega_${f}_last_run; chmod 0640 /var/lib/logstash/seal/.omega_${f}_last_run; done
sudo -u logstash env LOGSTASH_KEYSTORE_PASS="$KP" /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
systemctl restart logstash && journalctl -u logstash -f
```
Note : `seal-omega.conf` ne contient QUE les inputs ; le filtre et la sortie GELF
de `seal.conf` s'appliquent (pipeline fusionné). Ne pas y redéfinir filter/output.

## 4. Vérification

```
# Les evenements OMEGA doivent arriver, taggues seal_site=bx-seal-omega :
#   event_source:seal AND seal_site:bx-seal-omega
# Repartition par site (a ajouter aux dashboards si besoin) : pivot seal_site.
# Les detections/correlation couvrent OMEGA automatiquement (routage par domaine).
```

## 5. Rappels
- Rotation du mot de passe du compte de service OMEGA après mise en service.
- `seal_site` n'est présent que sur les événements ingérés APRÈS ce déploiement
  (l'historique QA déjà ingéré n'a pas le champ ; filtrer `NOT seal_site:bx-seal-omega`
  pour isoler la QA si nécessaire).
- Périmètre inchangé : pas de flux vidéo `VDO_*`, pas de `UserData.SearchHistory`.
