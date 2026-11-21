# Entra ID (Azure AD) — couverture SIEM & actions tenant

## Déjà intégré (rien à faire)
Le fetcher `omni-m365-fetch` collecte déjà via Microsoft Graph :
- **Sign-ins** (`/auditLogs/signIns`) → `event_source=m365 m365_type=signin` (mesuré : 3634+/7j).
- **Audits annuaire** (`/auditLogs/directoryAudits`) → `m365_type=audit` (1113+/7j).

**Détections Entra en place** (11) : `m365_brute_externe`, `m365_etranger` (connexion étrangère),
`m365_role` (changement de rôle), `m365_oauth_consent`, `m365_mail_forward`, `m365_mailbox_deleg`,
`m365_partage_externe`, `m365_risque`, + **ajoutées par `94-entra.sh`** : `m365_app_credential_add`
(secret/cert ajouté à une app = backdoor cloud), `m365_ca_change` (modif Conditional Access).

## ⚠️ Action 1 — débloquer les *risk detections* (Identity Protection)
**Constat mesuré** : `m365_type=risk = 0`, et **100 % des sign-ins remontent `risk_level=hidden /
risk_state=none`**. Le moteur de risque Azure ne calcule rien → la détection `m365_risque` reste muette.
Cause = **pas de licence Entra ID P2**. À faire côté tenant :

1. **Licence** — activer **Entra ID P2** (ou EMS E5 / M365 E5) sur les comptes à surveiller.
   *Sans P2, `identityProtection/riskDetections` renvoie 0 — ce n'est pas le fetcher.*
2. **Permission Graph** — sur l'app registration du fetcher, ajouter la permission **Application**
   (app-only) **`IdentityRiskEvent.Read.All`** (+ option `IdentityRiskyUser.Read.All`). Conserver
   `AuditLog.Read.All` + `Directory.Read.All` déjà en place.
3. **Consentement admin** — un Global Admin clique **« Accorder le consentement administrateur »**
   sur ces permissions (sinon token app-only sans scope → Graph 403 → risk reste 0).

**Vérif** : après ces 3 étapes, `m365_type=risk` doit passer > 0 et de nouveaux sign-ins remonter
`risk_level` ∈ {low, medium, high}. `m365_risque` se mettra alors à détecter.

## ⚠️ Action 2 — bloquer la *legacy auth* (bypass MFA)
**Constat mesuré** : **1461 authentifications « Authenticated SMTP »** (+ 41 « Other clients ») sur la
fenêtre. Les protocoles legacy (SMTP/IMAP/POP/ActiveSync de base) **ne supportent pas la MFA** → un
attaquant les utilise pour contourner la MFA en password-spray. À faire :
- **Conditional Access** : policy « Block legacy authentication » (ou Security Defaults).
- Vérifier quels comptes/services utilisent encore SMTP authentifié (apps d'envoi, MFP scan-to-mail) et
  les migrer (OAuth / SMTP via connecteur dédié) avant de bloquer.

> Une fois la legacy auth bloquée, `m365_brute_externe` reste la détection de spray sur les sign-ins modernes.
