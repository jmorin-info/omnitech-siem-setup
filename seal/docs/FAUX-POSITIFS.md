# SEAL — faux positifs et angles morts (revue du 16/07/2026)

Revue menée sur **7 jours de collecte réelle** (995 k accès, 717 k alarmes, 5,4 k audit)
et recoupée en SQL sur les vues sources. Elle a révélé autant de **faux négatifs**
(détections incapables de se déclencher) que de faux positifs.

## Résumé

| Règle | Constat | Correctif |
|-------|---------|-----------|
| **ALM-001** | **Morte** : `IS_INHIBITED` (bit) n'atteint jamais Graylog | vue SQL en varchar + requête tolérante |
| **ALM-004** | **Morte** : `IS_INTEMPESTIVE` est une *date*, pas un booléen | `_exists_:IS_INTEMPESTIVE` |
| **ALM-001/003/004** | Regroupement sur `target_object_label` (vide à 100 % dans l'index) | `trigger_code` (99,40 %) + `seal_site` |
| **ACC-006** | Regroupement sur un champ vide (0,00 % dans l'index) → alerte « refus sur UNE porte » déclenchée par 5 portes différentes | `target_object_id` (99,44 %) + `seal_site` |
| **ACC-007** | Idem + entité vide sur les événements hors badge | `+ _exists_:badge_number` |
| **EVT-002** | 76 alertes/7 j, **100 % faux positifs** | **parquée** + remplacée par DQ-001 |

## Le piège central : les colonnes `bit` sont perdues

`IS_INHIBITED` est renseignée sur **703 641 lignes / 703 641** en base. Elle est
présente sur **0 document** dans l'index.

Cause : Logstash convertit `bit` → booléen, et son output GELF **n'émet pas les
champs valant `false`**. Le champ n'atteint jamais Graylog. La détection ALM-001
(inhibition d'alarme, T1562.001) interrogeait donc `IS_INHIBITED:true` sur un
champ inexistant : **structurellement incapable de se déclencher**, tout en
apparaissant verte et active dans la console. Même mécanisme sur `IS_PRIORITY`.

Les colonnes `varchar` passent — c'est pourquoi `off_hours`, qui vaut la *chaîne*
`'true'`/`'false'`, fonctionne depuis le début.

> **Règle à retenir : ne jamais exposer une colonne `bit` à une vue SIEM.**
> La caster en varchar (`'true'`/`'false'`). Vérification :
> ```sql
> SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
> WHERE TABLE_NAME LIKE 'vw_Seal%' AND DATA_TYPE = 'bit';   -- doit être vide
> ```

Correctif : `/tmp/sql/01_fix_bit_columns.sql` (= `seal/sql/03_vw_SealAlarms_SIEM.sql`),
à jouer sur **QA et OMEGA**.

## Le deuxième piège : regrouper sur un champ non peuplé

Graylog ne signale pas un `group_by` sur un champ absent : il range tout dans un
bucket unique **`(Empty Value)`**. Visible dans les alertes réelles :
`ACC-006 ... : (Empty Value)`.

Taux de remplissage mesurés. **Deux populations différentes**, à ne pas confondre :
la vue SQL décrit la base QA ; l'index décrit ce qui est réellement collecté (très
majoritairement OMEGA). Un champ peut être renseigné dans l'une et absent de
l'autre — c'est le cas de `target_object_label`.

| Champ | Vue SQL (QA) | Index (tous sites) | Verdict |
|-------|--------------|--------------------|---------|
| `target_object_label` | 8,5 % (81 918 / 961 303) | **0,00 %** (1 / 997 481) | inutilisable |
| `target_object_id` | 99,5 % (956 154 / 961 303) | **99,44 %** (991 930 / 997 481) | clé des accès |
| `trigger_code` *(alarmes)* | 100 % (703 641 / 703 641) | **99,40 %** (715 015 / 719 303) | clé des alarmes, et **lisible** |
| `badge_number` | 0,04 % (399 / 961 303) | 0,13 % (1 328 / 997 481) | garde `_exists_` obligatoire |
| `identity_matricule` | 0,009 % (87 / 961 303) | 0,01 % (74 / 997 481) | pont badge→AD vide |

> **Piège de mesure** (rencontré, corrigé le 16/07) : par défaut OpenSearch plafonne
> `hits.total` à **10 000**, alors que les agrégations comptent juste. Rapporter un
> `exists` à ce total plafonné produit des pourcentages faux — jusqu'à dépasser
> 100 %. Toujours interroger avec `"track_total_hits": true`.

### `seal_site` : sain pour la détection, trompeur en historique

| Fenêtre | Présence de `seal_site` (accès) |
|---------|-------------------------------|
| 24 dernières heures | **99,91 %** |
| 7 derniers jours | 98,80 % |
| Tout l'historique | **3,63 %** |

Le champ est posé par Logstash (`add_field`) : le backfill historique, antérieur,
ne le porte pas. Les détections travaillent sur des fenêtres de 10 à 15 minutes,
donc sur une couverture proche de 100 % — regrouper par `seal_site` est sûr. En
revanche, **toute analyse rétrospective par site sur l'historique est faussée** :
96 % des événements anciens n'ont pas de site.

`trigger_code` porte les libellés réels : `ENTREE PRINCIPALE`, `LECT COURSIVE R+1`,
`PORTAIL OMEGA`. Les alertes d'alarme nomment désormais le lieu.

Conséquence concrète d'ACC-006 avant correctif : **toutes** les portes des **deux**
sites tombaient dans le même bucket. Cinq refus sur cinq portes différentes
déclenchaient « accès refusés répétés sur *une* porte » — et l'alerte ne disait pas
laquelle. Faux positif sur le fond *et* sur la forme.

## EVT-002 : la règle qui mesurait autre chose que ce qu'elle disait

`EVT-002` (« badge inconnu/non enrôlé présenté ») testait
`NOT _exists_:identity_matricule`. Or `identity_matricule` n'est renseigné que sur
**87 lignes / 961 303** (0,009 %). La règle ne mesurait donc pas l'inconnu d'un
badge mais **le remplissage du pont badge → AD** : tout badge légitime remontait
« inconnu ». 76 alertes en 7 jours sur 39 badges, 100 % de faux positifs.

Aucun réglage de seuil ne corrige cela. **Mais la cause n'est pas celle que
j'avais annoncée** : j'ai d'abord écrit qu'il manquait dans SEAL un identifiant
rattachable à l'annuaire, et que c'était donc une décision de gouvernance. C'est
**faux**. La colonne `milf.BADGES.MATRICULE` existe, et les vues la récupèrent
bien (`b.MATRICULE AS identity_matricule`). Mesure du 16/07 sur
`vw_SealIdentity_SIEM` :

| Site | Porteurs | Avec matricule | Avec badge |
|------|---------:|---------------:|-----------:|
| **OMEGA (production)** | 443 | **187 (42,2 %)** | 439 (99,1 %) |
| QA | 98 | 19 (19,4 %) | 61 (62,2 %) |

Le pont fonctionne donc pour **deux badges sur cinq** en production. `EVT-002`
se déclenchait sur les 58 % restants — des porteurs légitimes dont le matricule
n'a simplement pas été saisi. C'est un **remplissage de référentiel**, pas une
impossibilité technique : le taux monte dès que la saisie est complétée côté
gestion des badges.

D'où le choix : parquer `EVT-002` et **mesurer** le taux avec `DQ-001` au lieu
d'alerter dessus.

Réactivation, une fois le pont peuplé :
```bash
seal/detections/provision_detections.py --apply --enable-parked
```

## Volumétrie après correctif (simulée sur les 7 jours réels)

| Règle | Alertes / 7 j | Entités |
|-------|---------------|---------|
| ACC-006 | 10 | 2 portes |
| ACC-007 | 15 | 11 badges |
| ALM-003 | 0 | aucune effraction sur la période |
| ALM-004 | 0 | aucun flood sur la période |
| DQ-001 | 4 | 1 site |
| EVT-002 *(avant)* | **203** | 43 badges |

## Ce qui reste un angle mort assumé

- **Acquittement des alarmes** : `ACK_EVEN_ID` n'est renseigné que sur **6 lignes /
  703 641**. Le SLA ne mesure donc pas « alarme non *acquittée* » mais « alarme
  restée *ouverte* » (dernier statut `LIV`). C'est exploitable, mais il faut le
  dire : la dimension acquittement n'existe pas dans la donnée.
- **Pont badge → AD** : renseigné à **42 % en production** (187/443 porteurs).
  Ni impossible, ni cassé : à compléter par la saisie. Voir EVT-002.
- **`IS_INHIBITED` vaut `false` partout** : aucune alarme n'a jamais été inhibée.
  Le correctif ne déclenchera donc rien aujourd'hui — il garantit qu'une
  inhibition **future** sera vue.
- **88 % du flux « accès » est technique** (`SEM97`, perte de connexion lecteur,
  `event_outcome:na`) : sans incidence sur les détections (filtrées sur
  grant/deny), mais cela gonfle le stream et les tableaux de bord.
