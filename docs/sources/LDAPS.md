# LDAPS — Authentification Active Directory sur la console Graylog

*Objectif : comptes nominatifs AD pour la console (traçabilité ISO A.5.16/A.8.5),
le compte local `admin` ne servant plus que de secours.*

## 0. Choix retenus (12/06/2026)

- Compte de liaison : **`svc_siem`** (réutilisé — utilisateur standard,
  également utilisé pour le dépôt des sauvegardes).
- Compte de test / référence admin : **`adm-jmorin`**.
- DC cible : **bx-ad-01-it-vm.omnitech.security (10.33.50.250)**.
- Pré-requis pare-feu : règle FortiGate **425** (Réseau ELK → DC) doit
  inclure le service **LDAPS-GC** (636/3269) — `append service "LDAPS-GC"`.
- **Accès restreint aux membres du groupe « Admins du domaine »** (filtre
  LDAP `memberOf` récursif) : un compte AD hors groupe ne peut pas
  s'authentifier du tout.
- Rôle attribué automatiquement : **Admin** (population déjà restreinte).
- Compte local `admin` conservé en secours (coffre).

> **ÉTAT : OPÉRATIONNEL (12/06/2026).** Backend « Active Directory OMNITECH »
> actif (LDAPS 636, certificat vérifié par la Root CA interne). DN du groupe
> confirmé par LDAP : `CN=Admins du domaine,OU=Comptes_Service,OU=_Support,
> OU=Entreprise,DC=omnitech,DC=security`. Filtre testé : adm-jmorin (admin)
> admis, svc_siem (non-admin) rejeté. Règle FortiGate 425 : LDAPS-GC ajouté.

## 1. Pré-requis (côté AD — 5 minutes)

1. **Compte de liaison** (lecture seule, jamais interactif) :
   **`svc_siem`** — compte de service du domaine déjà existant (réutilisé,
   il sert aussi au dépôt des sauvegardes), mot de passe fort, « le mot de
   passe n'expire pas », aucune appartenance privilégiée. Le bind se fait au
   format UPN : `svc_siem@omnitech.security`.
2. **LDAPS actif sur les DC** : avec AD CS + auto-enrollment c'est déjà le
   cas en général. Vérification depuis le SIEM (contre le DC réellement
   ciblé) :
   ```bash
   echo | openssl s_client -connect bx-ad-01-it-vm.omnitech.security:636 \
     -CAfile /etc/graylog/certs/omnitech-rootca.crt 2>/dev/null | grep "Verify return"
   # attendu : Verify return code: 0 (ok)   <- confirmé en prod (14/06/2026)
   ```
   (La JVM de Graylog fait déjà confiance à la Root CA via `cacerts-omni.jks`.)
3. Règle FortiGate **425** (Réseau ELK → DC) : ajouter le service
   **LDAPS-GC** (TCP 636 + Global Catalog 3269) — `append service "LDAPS-GC"`.
   La règle n'ouvrait au départ que web+ping ; le service LDAPS-GC a bien été
   ajouté (cf. section 0).

## 2. Mise en place (côté SIEM)

```bash
# 1. renseigner les variables dans 00-vars.env :
LDAP_HOST='bx-ad-01-it-vm.omnitech.security'
LDAP_BIND_DN='svc_siem@omnitech.security'          # bind au format UPN
LDAP_BIND_PASS='********'
LDAP_REQUIRED_GROUP_DN='CN=Admins du domaine,OU=Comptes_Service,OU=_Support,OU=Entreprise,DC=omnitech,DC=security'
# (optionnels avec valeurs par défaut : LDAP_PORT=636, LDAP_SEARCH_BASE=DC=omnitech,DC=security)

# 2. executer :
bash /root/omnitech-siem-setup/33-ldaps-auth.sh
```

Le script crée le backend « Active Directory OMNITECH » (Active Directory,
LDAPS :636, `transport_security=tls`, `verify_certificates=true`), applique
le filtre LDAP restrictif (cf. section 3), attribue le rôle par défaut
**Admin**, puis l'ACTIVE. Le script est **idempotent** (rejoue sans casser un
backend déjà créé). Il vérifie d'abord le certificat LDAPS contre la Root CA
interne ; s'il est injoignable, il avertit mais continue (Graylog refusera
simplement les connexions tant que ce n'est pas corrigé).

## 3. Fonctionnement et attribution des rôles

- **Accès restreint par filtre LDAP** : le `user_search_pattern` du backend
  n'autorise QUE les membres (récursifs) du groupe « Admins du domaine ».
  Un compte AD hors de ce groupe est invisible au backend et **ne peut pas
  s'authentifier du tout** :
  ```
  (&(objectClass=user)
    (|(sAMAccountName={0})(userPrincipalName={0}))
    (memberOf:1.2.840.113556.1.4.1941:=CN=Admins du domaine,OU=Comptes_Service,OU=_Support,OU=Entreprise,DC=omnitech,DC=security))
  ```
  Le OID `1.2.840.113556.1.4.1941` (LDAP_MATCHING_RULE_IN_CHAIN) rend
  l'appartenance **récursive** (groupes imbriqués pris en compte).
- La population étant déjà restreinte aux administrateurs du domaine, le
  backend attribue **directement le rôle `Admin`** (`default_roles`) à la
  première connexion — pas de promotion manuelle à faire.
  > En édition Open Source il n'existe pas de team sync (mapping rôle ⇄ groupe
  > AD) ; le choix « filtre group-restricted + rôle Admin par défaut » est la
  > façon d'obtenir un accès admin réservé sans Enterprise.
- Connexion avec `sAMAccountName` (ou UPN) + mot de passe AD ; le nom complet
  affiché vient de `displayName`.
- Le compte local `admin` reste actif en secours (si l'AD est indisponible,
  la console reste administrable) — mot de passe au coffre.

## 4. Retour arrière

System → Authentication → désactiver le backend (l'authentification locale
reprend seule), ou via API : `POST /system/authentication/services/configuration`
avec `{"active_backend": null}`.

---
*Dernière revue : 14/06/2026 — faits vérifiés contre `33-ldaps-auth.sh`,
`00-vars.env` et le backend actif (API Graylog). Backend OPÉRATIONNEL,
certificat LDAPS vérifié (`Verify return code: 0`).*
