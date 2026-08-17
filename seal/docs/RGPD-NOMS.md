# RGPD-NOMS.md — Exposition nominative des porteurs de badge (opt-in par site)

Note de gouvernance. Autorite technique : `CONTRACT.md` (D1 minimisation).
Objet du present document : encadrer la SEULE derogation prevue a D1, a savoir
l'ajout du nom/prenom du porteur de badge dans le flux SIEM, via la vue
`dbo.vw_SealIdentity_Nominatif` (`seal/sql/05b_vw_SealIdentity_Nominatif.sql`).

## 1. Etat par defaut : pseudonyme, pas de nom

Par defaut, aucune vue SEAL n'expose de nom. L'identite est portee par le
`identity_matricule` (via `vw_SealIdentity_SIEM`), voire par le seul
`badge_number`. C'est un choix de MINIMISATION : le SIEM sait correler et
alerter sans stocker en continu qui est physiquement derriere chaque badge.
Ce mode reste le mode recommande et ne demande aucune formalite.

## 2. Le risque a bien peser avant d'activer les noms

Ajouter le nom au flux d'acces et d'alarmes transforme le SIEM en base de
SURVEILLANCE NOMINATIVE des deplacements et horaires des salaries :

- traitement a risque eleve (donnees de presence/mouvement rattachees a des
  personnes identifiees, sur la duree de retention SEAL : 12 a 24 mois selon
  le stream) ;
- finalite securite facilement detournable en controle managerial si l'acces
  n'est pas cloisonne ;
- effet cumulatif : correle aux autres sources SIEM, le nom devient un
  tracage transversal de l'activite de l'employe.

C'est pourquoi la vue nominative est LIVREE MAIS DESACTIVEE : sa simple
presence dans le depot ne l'active pas ; il faut un acte de deploiement ET un
GRANT explicites, par site.

## 3. Alternative proportionnee (recommandee par defaut)

Dans la plupart des cas, on n'a pas besoin du nom en continu : on en a besoin
PONCTUELLEMENT, lors d'une investigation. La demarche proportionnee est donc :

- conserver dans le SIEM le pseudonyme (matricule / badge) uniquement ;
- resoudre `matricule -> nom` A LA DEMANDE au moment d'une investigation
  legitime (requete ciblee cote annuaire / RH ou cote base SEAL), par une
  personne habilitee et avec tracabilite de la consultation ;
- ne jamais materialiser le nom dans les index SIEM.

Cette voie satisfait le besoin d'enquete tout en gardant le stock de donnees
minimise. Elle doit etre preferee tant qu'un besoin recurrent et documente ne
justifie pas le stockage nominatif permanent.

## 4. Procedure d'activation, PAR SITE

Le choix se fait naturellement par SEAL : chaque serveur a ses propres vues.
Activer les noms sur un site n'engage que ce site ; les autres restent
pseudonymises. Pour un site donne, activer UNIQUEMENT apres avoir coche
l'integralite de la checklist ci-dessous.

Checklist d'activation (site : __________, date : __________) :

- [ ] AIPD (analyse d'impact) realisee pour ce traitement et ce site.
- [ ] Base legale identifiee et documentee (finalite securite, proportionnalite,
      duree de conservation dediee justifiee).
- [ ] Accord formel DPO + RSSI (trace ecrite conservee).
- [ ] Information prealable du CSE et des salaries concernes (affichage /
      note de service / mise a jour du registre des traitements).
- [ ] Acces au dashboard / stream nominatif RESTREINT aux seuls habilites
      (role dedie cote Graylog, pas d'acces analystes standard).
- [ ] Journalisation des acces au contenu nominatif activee et revue
      periodiquement.
- [ ] Retention dediee decidee pour la donnee nominative (au plus courte
      possible ; ne pas heriter par defaut des 12/24 mois du flux).
- [ ] Point de reversibilite prevu (comment revenir au mode pseudonyme).

Mise en oeuvre technique une fois la checklist validee :

1. Deployer `05b_vw_SealIdentity_Nominatif.sql` sur CE SEAL (en plus, ou a la
   place, de `05_vw_SealIdentity_SIEM.sql`).
2. Ajouter DELIBEREMENT le droit de lecture au compte de service, par ex. :
   `GRANT SELECT ON OBJECT::dbo.vw_SealIdentity_Nominatif TO svc_graylog_seal;`
   (non pose par `90_provision.sql`, qui reste au strict minimum par defaut).
3. Cote SIEM : mapper le champ `identity_name` vers un champ DEDIE, l'affecter
   a un dashboard/stream a acces restreint, et NE PAS le diffuser dans les
   alertes/mails de triage generaux.

## 5. Coherence avec le CONTRACT

- `CONTRACT.md` D1 reste la regle par defaut : les vues SIEM standards
  n'exposent pas les noms. Le present document ne modifie pas D1 ; il decrit la
  seule exception gouvernee et la maniere de l'activer sans l'etendre.
- Le champ ajoute est nomme `identity_name`, coherent avec la famille
  `identity_matricule` / `identity_upn` de D4. Meme en nominatif, le perimetre
  reste borne : uniquement le nom d'usage ; toutes les autres PII de
  `milf.BADGES` (PHOTO, BIRTH_*, ADDRESS, etc.) demeurent EXCLUES.
- Desactivation par defaut = le comportement de reference. L'activation est un
  evenement de gouvernance trace, reversible, et local a un site.
