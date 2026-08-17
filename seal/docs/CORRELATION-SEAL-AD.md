# Pont d'identite SEAL x AD — correlation acces physique / logon logique (XCO)

## 1. Objet

Correler les evenements SEAL (acces physique : badge, alarmes, audit hyperviseur)
aux logons Windows / M365 (identite logique) de la MEME personne. La cle de
jointure est l'UPN canonique (`identity_upn`, minuscule), champ commun aux deux
mondes :

- cote Windows/M365 : `identity` (deja normalise, UPN minuscule) ;
- cote SEAL : `identity_upn`, ABSENT en base (le SQL ne fournit que
  `identity_matricule`, cf `CONTRACT.md` D4) -> resolu SIEM-side par ce pont.

Chaine de resolution :

```
badge (EVEN_PHYSICAL_NUMBER) -> identity_matricule (milf.BADGES.MATRICULE, jointure SQL)
        -> lookup omni-seal-identity (matricule -> UPN, depuis l'AD)
        -> identity_upn (UPN canonique minuscule)  ==  identity (Windows/M365)
```

## 2. Architecture

| Composant | Fichier | Role |
|-----------|---------|------|
| Extraction AD | `seal/graylog/regen-seal-identity.sh` | LDAPS (636, lecture seule, meme compte de liaison que la console) -> CSV `matricule,upn` dans `/etc/graylog/lookup/seal-identity.csv`. UPN mis en minuscule (forme canonique). Idempotent (ecriture atomique + remplacement conditionnel). |
| Lookup Graylog | `omni-seal-identity` (adapter csvfile + cache guava + table) | Provisionne par `provision_seal.py` (`ensure_identity_lookup`). Cle `matricule`, valeur `upn`. Recharge auto <=60 s a chaque changement du CSV. |
| Regle pipeline | `seal/graylog/pipelines/14-seal-identity-upn.rule` | Sur tout message SEAL portant `identity_matricule`, pose `identity_upn = lowercase(lookup_value("omni-seal-identity", identity_matricule))`. Stage TERMINAL des 3 pipelines SEAL (apres la normalisation qui pose le placeholder `""`). Pas de ternaire. |
| Cote AD/Windows | `seal/graylog/pipelines/13-identity-mirror.rule` (hors perimetre SEAL) | Pose `identity_upn` sous la MEME forme canonique sur les logons Windows/M365. Doit etre integre par le proprietaire de la couche AD pour que le join fonctionne. |
| Correlation XCO | `oms-xdr/oms_xdr/rules.yaml` | Signaux `S_SEAL_BADGE_IN`, `S_SEAL_CONSOLE_LOGON` (keyes `identity_upn`) + regles `CR_XCO_IMPOSSIBLE_PRESENCE`, `CR_XCO_CONSOLE_NO_BADGE`. |

Flux :

```
AD (LDAPS 636) --regen-seal-identity.sh(cron)--> /etc/graylog/lookup/seal-identity.csv
      --adapter csvfile--> lookup omni-seal-identity
      --regle 14 (stage terminal)--> identity_upn sur les events SEAL
      --oms-xdr (S_SEAL_* keyes identity_upn)--> join avec S_LOGON_SUCCESS / S_M365_FOREIGN_SIGNIN
```

## 3. Regles XCO livrees

- `CR_XCO_IMPOSSIBLE_PRESENCE` (critical) : badge-in physique SEAL
  (`S_SEAL_BADGE_IN`) + sign-in M365 depuis un pays hors egress
  (`S_M365_FOREIGN_SIGNIN`) pour le meme `identity_upn`. Presence physique et
  connexion etrangere simultanees = impossible -> compromission de compte probable.
  Expressible et fiable des que le pont est en place.
- `CR_XCO_CONSOLE_NO_BADGE` (high, a confirmer) : connexion a la console
  hyperviseur (`S_SEAL_CONSOLE_LOGON`) rattachee au logon Windows du meme
  `identity_upn` (`S_LOGON_SUCCESS`). Intention = "console sans badge-in
  physique" ; voir la limite §5.

## 4. Ce qu'il faut AJOUTER SUR LA VM (deploiement)

1. Peupler la lookup : deposer `regen-seal-identity.sh` et le planifier en cron
   (ex chaque nuit). Pre-requis : `ldapsearch` (paquet `ldap-utils`),
   `LDAP_BIND_DN` / `LDAP_BIND_PASS` dans l'environnement (jamais en clair),
   Root CA interne dans `/etc/graylog/certs/omnitech-rootca.crt`, regle FW
   ELK -> DC en TCP 636 (deja ouverte pour la console, cf `33-ldaps-auth.sh`).
   Exemple cron :
   ```
   # /etc/cron.d/seal-identity  (env dans /etc/graylog/seal-ldap.env, mode 600)
   17 3 * * *  root  . /etc/graylog/seal-ldap.env; /root/omnitech-siem-setup/seal/graylog/regen-seal-identity.sh >> /var/log/seal-identity.log 2>&1
   ```
2. Provisionner la lookup + la regle + la connexion aux pipelines :
   `provision_seal.py --apply` (cree `omni-seal-identity`, charge la regle 14,
   l'ajoute en stage terminal des 3 pipelines SEAL — idempotent).
3. Cote couche AD (hors SEAL) : integrer `13-identity-mirror.rule` (ou equivalent)
   pour poser `identity_upn` sur les logons Windows/M365 avec la MEME forme
   canonique. Sans cela, le champ SEAL n'a rien avec quoi se joindre.

## 5. Ce qu'il faut CONFIRMER

- **Attribut AD du matricule.** `regen-seal-identity.sh` lit l'attribut
  `SEAL_MATRICULE_ATTR` (defaut `employeeID`). CE DEFAUT N'EST PAS VALIDE. Le
  matricule SEAL observe ressemble a des INITIALES (ex `JPA`, `PGE`) et non a un
  identifiant numerique -> il n'y a AUCUNE garantie que ce soit `employeeID`.
  Candidats a tester cote AD : `employeeID`, `employeeNumber`,
  `extensionAttribute1..15`, `initials`. Verification manuelle :
  ```
  ldapsearch -x -H ldaps://bx-ad-01.omnitech.security:636 -D "$LDAP_BIND_DN" -y pw \
    -b "DC=omnitech,DC=security" "(sAMAccountName=<compte connu>)" \
    employeeID employeeNumber initials extensionAttribute1
  ```
  Ajuster `SEAL_MATRICULE_ATTR` une fois l'attribut porteur du matricule identifie.
- **Format et unicite du matricule.** Confirmer que la valeur AD choisie correspond
  EXACTEMENT (casse comprise ; le lookup est case-insensitive cote Graylog) au
  `identity_matricule` produit par le SQL SEAL, et qu'elle est unique par personne.
- **Forme canonique de l'UPN des deux cotes.** `identity_upn` (SEAL) et `identity`
  (Windows/M365) doivent etre STRICTEMENT identiques (UPN minuscule). Un ecart de
  casse/domaine fait echouer le join SILENCIEUSEMENT.

## 6. Limites actuelles (franc)

- **Volume de resolution tres faible.** `identity_matricule` n'est peuple que sur
  ~35 events aujourd'hui et `identity_upn`=0. Tant que la couverture
  badge -> matricule ne progresse pas cote SQL (jointure `milf.BADGES.MATRICULE`),
  la resolution badge -> UPN reste marginale : les regles XCO ne produiront quasi
  aucun incident. Le pont est cable et correct, mais son ALIMENTATION est le vrai
  goulet -> a ameliorer cote extraction SEAL (fiabiliser la jointure badge/matricule).
- **Pas d'anti-join dans le moteur oms-xdr.** `CR_XCO_CONSOLE_NO_BADGE` vise une
  ABSENCE ("connexion console SANS badge-in"), non exprimable : le moteur ne fait
  que `require_all` / `any_of` (presence). La regle livree APPROCHE l'intention
  (console + logon Windows du meme UPN) mais NE prouve pas l'absence de badge ->
  severity `high` "a confirmer", verification badge laissee a l'analyste. Piste
  d'evolution : signal d'enrichissement `badged_in_today` par identite (lookup), ou
  operateur de negation dans le moteur.
- **Cote audit hyperviseur, l'UPN dependra d'un pont supplementaire.** Les events
  audit portent `actor_login` (compte console) et non toujours un
  `identity_matricule` de badge. `S_SEAL_CONSOLE_LOGON` ne se declenchera donc que
  si `identity_upn` a pu etre resolu sur ces events (piste : comptes console marques
  "Windows account", `actor_login` -> compte AD). A cabler separement si besoin.
- **Dependance a la couche AD.** Sans `13-identity-mirror` cote Windows/M365, le
  champ `identity`/`identity_upn` n'existe pas cote logon -> aucun join possible.
  Cette couche est hors du perimetre SEAL et doit etre livree en parallele.
