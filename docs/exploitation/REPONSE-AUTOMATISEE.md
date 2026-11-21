# Détection avancée & réponse automatisée — Canari AD + SOAR

*Version 1.0 — 12/06/2026 — Classification : interne — Réf ISO A.8.16, A.5.26.*

Ce document décrit les deux dispositifs « actifs » du SIEM : le **compte
canari** (détection d'intrusion à très faible bruit) et le **SOAR-light**
(réponse automatique par blocage d'IP).

---

## 1. Compte canari AD (détection d'intrusion interne)

### Principe
Un compte Active Directory **leurre**, crédible et attractif (il a l'air d'un
compte de service SQL privilégié), mais **sans aucun privilège réel** et qui
n'est **jamais utilisé légitimement**. Toute authentification, tentative ou
requête Kerberos le concernant ne peut être que le fait d'un attaquant qui
énumère l'annuaire, fait du brute force, du Kerberoasting ou du mouvement
latéral. **Taux de faux positifs quasi nul par construction.**

### Mise en œuvre
| Élément | Détail |
|---|---|
| Compte AD | `windows/New-OmniCanary.ps1` — mot de passe aléatoire jamais communiqué, `PasswordNeverExpires`, **SPN MSSQLSvc** (piège à Kerberoasting → génère un 4769), `logonHours` nuls, aucune appartenance privilégiée |
| Détection SIEM | lookup `omni-canary` (CSV `lookups/canary-accounts.csv`) + règle pipeline `omni-winsec-10-canary` (matche user / TargetUserName / SubjectUserName / ServiceName) |
| Alerte | **« OMNI - COMPTE CANARI touché »** — P3, mail + Teams, immédiate |
| Provisionnement | `35-canary.sh` (lookup + alerte), puis rejouer `12-graylog-pipelines.sh` |

### Exploitation
- **Ajouter un canari** : éditer `canary-accounts.csv` + relancer `35-canary.sh`.
- **Déclenchement = incident** : toute alerte canari est traitée en priorité
  (cf. playbook P-4, PRO §6). Identifier le poste/IP source immédiatement.
- Recommandé : un canari par zone sensible (un nom différent, crédible).

---

## 2. SOAR-light (blocage automatique d'IP attaquantes)

### Principe
Quand une attaque réseau est détectée (brute force / spraying VPN), le SIEM
publie l'IP source dans une **liste de blocage** que le FortiGate lit en
*External Threat Feed* et bloque. Architecture **découplée** : le SIEM n'a
**aucun identifiant** sur le pare-feu (sécurité), et le blocage **expire seul**.

### Chaîne complète
```
Alerte Graylog (Force brute VPN / Password spraying)
   │  notification HTTP
   ▼
omni-soar (service, 127.0.0.1:8088)
   │  sécurités : jamais RFC1918, jamais SOAR_WHITELIST,
   │  seuil SOAR_MIN_HITS, plafond SOAR_MAX, TTL SOAR_TTL_HOURS
   ▼
/var/www/siem-kit/soar/blocklist.txt   (servi en HTTPS)
   │  poll toutes les 2 min
   ▼
FortiGate External Connector "OMNI_SOAR_Blocklist"
   │
   ├─ local-in-policy  → bloque le portail SSLVPN (trafic vers le boîtier)
   └─ firewall policy  → bloque les services publiés (trafic traversant)
   ▼
Blocage — expiration automatique après TTL (défaut 24 h)
```

### Composants
| Élément | Rôle |
|---|---|
| `/usr/local/sbin/omni-soar` | service webhook → décision → feed (GELF de traçabilité) |
| `/usr/local/sbin/omni-soar-expire` (+ timer horaire) | retire les IP expirées |
| `36-soar.sh` | crée la notification HTTP, l'attache aux alertes VPN/spraying, crée l'alerte de traçabilité |
| `fortigate/06-soar-threatfeed.conf` | connecteur + policies FortiGate |
| Alerte **« OMNI - SOAR : IP bloquée automatiquement »** | mail à chaque blocage |

### Garde-fous (paramètres `00-vars.env`)
| Paramètre | Défaut | Rôle |
|---|---|---|
| `SOAR_WHITELIST` | (vide) | **IP publiques à NE JAMAIS bloquer** : sites OMNITECH, peers IPsec, admins. À renseigner. |
| `SOAR_MIN_HITS` | 5 | occurrences minimum de l'IP dans le backlog pour bloquer |
| `SOAR_MAX` | 500 | plafond d'IP simultanément bloquées |
| `SOAR_TTL_HOURS` | 24 | durée de blocage avant expiration auto |

Sécurités structurelles : **aucune IP privée** (RFC1918) n'est jamais bloquée ;
chaque blocage est **tracé** (mail + GELF) ; un faux positif se **débloque
seul** au bout du TTL.

### Exploitation
- **Voir les IP bloquées** : console SIEM (page Sauvegardes / recherche
  `event_action:ip_bloquee`) ou FortiGate GUI (*External Connectors → View
  Entries*). Les commandes `diagnose` CLI ne sont pas supportées sur toutes
  les versions FortiOS.
- **Débloquer manuellement** : retirer l'IP de `/var/lib/omni-soar/blocklist.json`
  puis `python3 /usr/local/sbin/omni-soar-expire`.
- **Compléter la whitelist** : indispensable avant exploitation réelle —
  ajouter les IP publiques fixes des sites et des admins.
- **Test de bout en bout** : injecter une IP de test dans le feed et vérifier
  qu'elle est lue côté FortiGate (poll ≤ 2 min, visible dans les logs nginx).

> ⚠️ Le SOAR agit **automatiquement** sur le pare-feu. Maintenir la whitelist
> à jour est une responsabilité d'exploitation (revue mensuelle, PRO §2).

## Évolution — SOAR avancé (cadrage)

Le blocage d'IP ci-dessus est **PB-01** (en production). Les playbooks suivants
sont **conçus**, en attente de l'**API NinjaOne** (cf. **`SOAR-PLAYBOOKS.md`**) :
- **PB-02 Isoler un hôte** compromis (ransomware / LSASS / lateral confirmé).
- **PB-03 Désactiver un compte** (s'appuie sur le champ `identity`) — canari /
  impossible travel / DCSync.
- **PB-04 Ouvrir un ticket** d'incident pré-rempli ; **PB-05 Enrichir IOC**.

Garde-fous renforcés (mêmes principes que PB-01) : **jamais** un contrôleur de
domaine / le SIEM / l'hyperviseur / un compte break-glass ; **dry-run** d'abord ;
actions réversibles et tracées. Tant que NinjaOne n'est pas branché, l'isolation
et la désactivation restent **manuelles** (cf. PROCEDURE-INCIDENT §5).
