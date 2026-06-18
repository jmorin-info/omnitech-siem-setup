# Guide du SIEM OMNITECH — comprendre le système en 15 minutes

> Ce document explique, **en langage simple**, à quoi sert ce SIEM, ce qu'il
> surveille, et comment lire ses écrans. Il s'adresse à **toute personne** :
> direction, auditeur, nouvel arrivant, technicien. Aucun prérequis en
> cybersécurité — les termes techniques sont définis dans le **glossaire** en fin
> de document.

---

## 1. C'est quoi, un SIEM ? (en une phrase)

Un **SIEM** (Security Information and Event Management) est la **boîte noire de la
sécurité** de l'entreprise : il **collecte** en continu les journaux de tous les
équipements (serveurs, postes, pare-feu, cloud Microsoft 365…), les **analyse**
pour repérer ce qui est anormal ou malveillant, et **alerte** l'équipe quand
quelque chose cloche. C'est l'outil qui permet de **détecter une attaque** et de
**mener l'enquête** après coup.

Le nôtre est bâti sur **Graylog** (le moteur de collecte/recherche) + **OpenSearch**
(la base qui stocke les journaux) + une **couche d'analyse maison** qui va
au-delà de ce que Graylog sait faire (détection comportementale, corrélation
d'attaques, carte des menaces…).

---

## 2. Le parcours d'un journal (vue d'ensemble)

```
   Postes / Serveurs Windows ─┐
   Pare-feu FortiGate ────────┤
   Microsoft 365 / Entra ─────┼─►  COLLECTE   ─►  NORMALISATION  ─►  DÉTECTION  ─►  ENRICHISSEMENT  ─►  STOCKAGE
   vSphere / ESXi ────────────┤    (Graylog)      (champs unifiés)    (règles)     (MITRE, score)      (OpenSearch)
   Sauvegardes Veeam ─────────┘                                                                              │
                                                                                                            ▼
   ANALYSE MAISON (toutes les X minutes)  ◄───────────────────────────────────────────  TABLEAUX DE BORD + ALERTES
   • score de risque par entité (UEBA)                                                    (écrans SOC + e-mail/Teams)
   • voyage impossible, balise C2, tunnel DNS, anomalie de volume
   • corrélation d'incidents (kill-chain)
```

**En clair :** chaque événement est reçu, rangé dans un format commun, comparé à
des règles de détection, étiqueté (ex. « accès mémoire LSASS = vol
d'identifiants »), associé à une technique d'attaque connue (**MITRE ATT&CK**) et
à un **score de risque**, puis stocké. En parallèle, des programmes d'analyse
tournent en boucle pour repérer des comportements suspects et **regrouper les
alertes en incidents**.

---

## 3. Les tableaux de bord — quelle page répond à quelle question ?

Tout est dans le dashboard **« OMNI - SOC »** (menu *Dashboards*). Les pages sont
classées par thème.

| Page | À quelle question elle répond |
|------|-------------------------------|
| **Direction** | « Globalement, ça va ? » Posture en 10 secondes : volume, détections, **incidents critiques**, **entités à risque**, tendances vs la veille. *Page pour la direction.* |
| **Alertes** | « Qu'est-ce qui a sonné ? » La file de toutes les détections, à trier. |
| **Incidents** | « Y a-t-il une attaque en cours ? » Les détections d'un même hôte/compte **regroupées en récit d'attaque** ordonné (la *kill-chain*). |
| **ATT&CK** | « Quelles techniques d'attaque observe-t-on ? » Lecture via le référentiel mondial MITRE ATT&CK. |
| **UEBA / NDR** | « Qui est le plus à risque, et y a-t-il un comportement anormal ? » Score par entité + voyage impossible, balise C2, tunnel DNS, anomalie de volume. |
| **Santé collecte** | « Mes sources remontent-elles bien ? » Couverture, hôtes muets (*go-dark*). |
| **Identité AD** | « Qui se connecte, qui échoue ? » Authentifications Active Directory. |
| **Comptes à privilèges** | « Que font les comptes admin ? » Surveillance renforcée des comptes sensibles. |
| **Comptes & conformité** | « Cycle de vie des comptes, PKI, conformité. » |
| **M365 / M365 Activité** | « Que se passe-t-il dans le cloud Microsoft ? » Connexions, partages, mails. |
| **Endpoint / Hunting** | « Que font les postes de travail ? » Processus, et **chasse** aux techniques avancées. |
| **Réseau / VPN & Exposition / Cartographie** | « Quel trafic, d'où, vers où ? » Pare-feu, VPN, géographie. |
| **vSphere / Sauvegardes / Certificats** | « Mon infra (virtu, backup, PKI) est-elle saine ? » |
| **Vulnérabilités** | « Quels hôtes sont exposés à une faille exploitée ? » (façon Wazuh, via CISA KEV). |
| **Investigation** | « Je veux enquêter sur X. » Page libre : tapez `host:BX-SRV01` ou `user:adm-jmorin` dans la barre de recherche, tout se filtre. |

**Astuce de lecture :** chaque widget a une icône **ⓘ** (au survol) qui explique
ce qu'il montre et ce qu'un pic signifie. Les cellules se **colorent** en orange
(à surveiller) ou rouge (critique) automatiquement.

---

## 4. La couche d'analyse « au-delà de Graylog » (expliquée simplement)

Ces analyses calculent des choses qu'un moteur de recherche classique ne sait pas
faire. Elles tournent automatiquement et réinjectent leurs résultats dans les
écrans.

- **Score de risque d'entité (UEBA)** — donne à chaque hôte et chaque compte une
  **note sur 100**, en fusionnant toutes ses alertes, ses vulnérabilités, ses
  échecs de connexion, etc. Permet de dire « commence par traiter celui-là ».

- **Voyage impossible** — si un même compte se connecte depuis la France puis,
  20 minutes plus tard, depuis un autre continent, c'est **physiquement
  impossible** : le compte est probablement piraté. On calcule la distance et la
  vitesse nécessaire entre deux connexions.

- **Balise C2 (beaconing)** — un poste infecté « appelle la maison » à intervalle
  **très régulier** (toutes les 60 s par exemple). On mesure cette régularité
  pour repérer un canal de commande caché.

- **Tunnel DNS** — technique pour **faire sortir des données en douce** en les
  encodant dans des requêtes DNS. On détecte les noms de domaine au contenu
  « aléatoire » (haute entropie) et très longs.

- **Anomalie de volume** — si une source se met soudain à émettre 10× plus (ou
  s'arrête net), c'est suspect. On compare à son habitude **à la même heure** des
  jours précédents.

- **Corrélation d'incidents** — au lieu de noyer l'analyste sous 50 alertes, on
  **regroupe** celles d'un même hôte en **une histoire** : *« Exécution →
  contournement de défense → vol d'identifiants → tentative de ransomware »*.

---

## 5. Les programmes automatiques (qui tourne, quand)

Ce sont des « robots » planifiés (timers systemd). On n'a **rien à lancer à la
main**.

| Programme | Fréquence | Rôle |
|-----------|-----------|------|
| `omni-collect-health` | 1 h | Couverture de collecte + détection des hôtes muets (go-dark) |
| `omni-vuln-scan` | 1 j | Croise l'inventaire logiciel avec les failles activement exploitées (CISA KEV) |
| `omni-ueba-score` | 30 min | Recalcule le score de risque de chaque entité |
| `omni-ueba-geo` | 30 min | Voyage impossible |
| `omni-ndr-beacon` | 6 h | Balises C2 |
| `omni-ndr-dns` | 1 h | Tunnels DNS |
| `omni-ueba-volume` | 1 h | Anomalies de volume |
| `omni-incident-correlate` | 15 min | Regroupe les détections en incidents |
| `omni-geo-flux` | 30 s | Alimente la carte cyber temps réel |
| `omni-monthly-report` | 1er du mois | Génère + envoie le rapport exécutif PDF |
| `omni-weekly-report` | hebdo | Rapport hebdomadaire e-mail |

---

## 6. Les alertes — comment c'est priorisé

Quand une règle se déclenche, une **notification** part (e-mail + Teams). Trois
niveaux :

- **P3 (critique)** — action immédiate (sabotage de journaux, DCSync, ransomware,
  incident corrélé critique…).
- **P2 (important)** — à traiter vite (balise C2, tunnel DNS, hôte go-dark, entité
  UEBA ≥ 80, voyage impossible…).
- Anti-spam : une même alerte qui persiste n'est **pas renvoyée en boucle**
  (délai de 6 h pour les conditions qui durent).

---

## 7. La carte cyber temps réel

Adresse : **`https://<siem>/kit/carte-cyber.html`**. Elle montre, sous forme
d'**arcs animés sur une carte du monde**, les attaques qui visent l'entreprise
(connexions bloquées, IP malveillantes, attaques VPN…), avec leur **pays
d'origine**. Mise à jour toutes les 30 secondes. *Idéal pour un écran mural SOC.*

---

## 8. Conservation des journaux & conformité (ISO 27001)

- **Dossier sécurité conservé 12 mois** (Windows, Sysmon, M365, vSphere…) ;
  **trafic pare-feu 90 jours** (gros volume, valeur forensic plus courte).
- Le bruit à faible valeur est filtré pour tenir dans l'espace disque.
- Politique détaillée : `docs/POLITIQUE-RETENTION.md` (preuve d'audit, mappée aux
  contrôles ISO 27001 A.8.15 / A.8.16 / A.8.17).

---

## 9. Par où commencer quand on arrive le matin (routine)

1. **Direction** — un coup d'œil : des incidents critiques ? des entités à risque ?
2. **Incidents** — lire les récits d'attaque du jour, traiter les *critiques*.
3. **UEBA / NDR** — vérifier le top des entités à risque, les détections
   comportementales.
4. **Santé collecte** — s'assurer que toutes les sources remontent (couverture
   ~100 %, aucun hôte go-dark).
5. Boîte mail / Teams — traiter les alertes reçues.

---

## 10. Glossaire (pour les non-spécialistes)

| Terme | Explication simple |
|-------|--------------------|
| **Journal / log** | Trace écrite d'un événement (connexion, fichier ouvert, paquet réseau…). |
| **Détection / alerte** | Un événement qui correspond à une règle « suspecte ». |
| **MITRE ATT&CK** | Catalogue mondial des techniques utilisées par les attaquants (chaque technique a un code Txxxx). |
| **Kill-chain** | Les étapes successives d'une attaque, dans l'ordre. |
| **Incident** | Plusieurs détections liées, regroupées en un seul cas à traiter. |
| **UEBA** | Analyse du comportement des utilisateurs/machines pour détecter l'anormal. |
| **NDR** | Détection sur le trafic réseau (balises, tunnels…). |
| **LSASS** | Processus Windows qui détient les mots de passe en mémoire — cible n°1 des voleurs d'identifiants. |
| **DCSync** | Technique pour voler tous les mots de passe d'un domaine Active Directory. |
| **Beaconing / C2** | Canal de communication caché entre un poste infecté et l'attaquant. |
| **Tunnel DNS** | Faire sortir des données discrètement via le service DNS. |
| **go-dark** | Un hôte qui cesse soudain d'émettre des journaux (panne… ou attaquant qui coupe la surveillance). |
| **KEV** | Liste officielle (CISA) des failles **activement exploitées** par des attaquants. |
| **Entropie** | Mesure du « désordre » d'un texte ; un texte très aléatoire (donc encodé) a une entropie élevée. |
| **Pare-feu / deny** | Équipement qui filtre le réseau ; « deny » = connexion bloquée. |

---

*Document de référence — SIEM OMNITECH Security. Pour le détail technique
d'implémentation, voir `CONTEXT.md`. Pour la politique de rétention,
`docs/POLITIQUE-RETENTION.md`.*
