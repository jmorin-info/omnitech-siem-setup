# oms-graph — Jumeau d'attaque / analyse d'exposition (OMNI Sentinel, Pilier 2)

Reconstruit **passivement** (sans sonde AD, depuis la télémétrie de logons déjà
collectée par le SIEM) un graphe d'**exposition** de l'environnement OMNITECH, et le
met au service de la **défense** : prioriser le durcissement et **pré-positionner les
leurres** (Pilier 1 / déception).

## Modèle
Deux arêtes dérivées des journaux Windows :
- **HasSession** (`compte → hôte`) : EID 4624, LogonType 2/10/11 (console/RDP/cached) —
  *les identifiants du compte sont exposés sur cet hôte*.
- **AdminTo** (`compte → hôte`) : EID 4672 (privilèges spéciaux) — *le compte est
  administrateur de cet hôte*.

Graphe de **propagation de compromission** : contrôler un hôte ⇒ moissonner les comptes
qui y ont une session ; contrôler un compte ⇒ contrôler les hôtes qu'il administre.

## Calculs
- **Exposition des joyaux** : quels pieds-à-terre atteignent chaque joyau (DC, SIEM,
  Veeam, PKI, fichiers, vSphere) et en combien de sauts.
- **Chokepoints** : comptes/hôtes sur le plus de chemins → où durcir / poser un leurre.
- **Rayon de souffle** : si X compromis, combien d'hôtes/joyaux deviennent atteignables.
- **Points uniques** : comptes de gestion (RMM/sync) admin partout → PAM + tiering.
- **Recommandations de leurres** : où poser un leurre (88) pour intercepter le plus de
  chemins, avec marquage « déjà couvert » via le registre `omni-deception`.

## Anti-bruit (mesuré)
Comptes machine (`*$`), système et virtuels (DWM/UMFD/MSSQL$/IUSR…) exclus ; comptes de
gestion ubiquitaires (admin de > N hôtes) sortis des chemins latéraux et rapportés à part
(sinon ils relient tout à tout).

## Usage
```
oms-graph analyze [--window 14d] [--top N] [--push]
```
Sans `--push` : affiche + écrit l'artefact JSON (`/var/lib/omni-mobile/attack-graph.json`,
lu par la console SOC). Avec `--push` : réinjecte les chemins en GELF
(`event_source=attack_path`, **informationnel, sans alert_tag** — c'est une posture, pas
une alerte). Lecture **passive** ; n'exécute **aucune** action sur le SI.

Déploiement : `89-attack-graph.sh` (venv + config `/etc/oms-graph` + timer quotidien +
routage vers « OMNI - Interne SIEM »).
