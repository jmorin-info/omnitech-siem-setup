# OMNI Sentinel — Plan de semis des leurres (DÉCEPTION)

> **Statut : DRY-RUN — action de Julien (RSSI).** La couche de *détection* (le piège) est
> déjà **armée et vérifiée** (script `88-deception-honeytokens.sh`, lookup `omni-deception`,
> 5 règles, 3 alertes). Ce document décrit l'**appât** à déposer pour que les pièges se
> referment. **Collision vérifiée = 0** sur 30 j pour tous les leurres ci-dessous.

## Règles d'or (sinon faux positif ou risque)

1. **Tenant co-managé `invissys.com` : INTERDIT.** Tous les leurres ci-dessous se posent
   exclusivement sur l'AD / l'infra **OMNITECH.SECURITY**.
2. **Discipline de dormance (le seul vecteur de FP).** Un compte leurre doit rester
   **inerte** : jamais câblé à un sync (MSOL/ADSync), un RMM (ninjaone), un outil de
   sauvegarde, ou un scanner authentifié. *Aucun usage = aucun événement = aucun FP.*
3. **Compte désactivé + mot de passe long aléatoire.** Le leurre ne doit jamais pouvoir
   être utilisé réellement ; seul l'attaquant qui *tente* l'utilise → c'est le signal.
4. **Ajouter un leurre = 1 ligne dans `lookups/deception-decoys.csv`** (key,type) →
   actif en < 60 s (re-lecture CSV), sans toucher au code. Relancer `88` pour redéployer le CSV.

## Carte d'environnement (dérivée en direct des données)

- **Nommage hôtes** : Schema dominant: <site>-<fonction|service>-<token>-<type>, tout en minuscules. Site: 'bx' (Bordeaux, siege, ~90% du parc), 'iv'/'in' (site secondaire), 'lc', 'vm-paca' (site PACA), 'vm-bdx'/'vm-dev' (VMs Bordeaux/dev). Fonction/service (2e 
- **Nommage comptes** : Domaine AD: OMNITECH.SECURITY (NetBIOS OMNITECH), domaine DNS omnitech-security.fr. Trois classes nettes: (1) UTILISATEURS humains = login en minuscules, deux formats coexistants -> ancien format 'initiale+nom' colle (jmorin, psoubieille, v
- **Comptes de service** : Pattern dominant 'svc_<service>' en minuscules avec underscore: svc_siem, svc_intranet. Variante minoritaire avec tiret 'svc-<service>': svc-fortimanager. Pour un leurre credible: privilegier 'svc_' (
- **Contrôleurs de domaine** : bx-ad-01-it-vm, bx-ad02-it-vm, vm-paca-ad1 (site PACA, derive du compte machine VM-PACA-AD1$ ; non emetteur de logs 4768 dans le SIEM mais authentifie comme DC distant)
- **Joyaux (cibles protégées par les leurres)** :
  - `bx-ad-01-it-vm + bx-ad02-it-vm (Contoleurs de domaine AD OMNITECH.SECURITY)` — Emetteurs exclusifs des EID 4768/KDC (144k + 118k). Compromission = controle total du domaine (DCSync, Golden Ticket, creation de comptes). 
  - `vm-paca-ad1 (DC du site distant PACA)` — Compte machine VM-PACA-AD1$ s'authentifie en DC ; replication AD = meme niveau de confiance que les DC de Bordeaux, point de pivot inter-sit
  - `bx-it-graylog-vm (SIEM Graylog)` — Le SIEM lui-meme. Sa compromission aveugle la detection et permet l'effacement des traces. Compte associe svc_siem. (NB MEMORY designe bx-it
  - `bx-veeam-it-sv + bx-veeam-prx1 + bx-veeam-prx2-it-vm (infra de sauvegarde Veeam)` — Cible privilegiee ransomware : detruire/chiffrer les sauvegardes supprime la capacite de restauration et maximise le levier d'extorsion. Com
  - `vaultwarden.omnitech-security.fr (coffre de mots de passe Vaultwarden)` — Stockage centralise de secrets/mots de passe (451k evts). Une seule compromission expose des credentials vers tout le parc = escalade massiv
  - `bx-pki2022 + bx-info-eset-vm / ADCS (PKI/ESET)` — PKI 2022 (ADCS) : abus de gabarits de certificats (ESC1-8) = persistance et usurpation d'identite a l'echelle du domaine. ESET = console EDR
  - `bx-files-it-vm (serveur de fichiers) + Omnitech-SSRS (SQL Server Reporting Services)` — Donnees metier sensibles centralisees (partages SMB) et base SQL applicative. Cibles directes d'exfiltration et de chiffrement.
  - `vcenter + bx-esxi-01..04-it (vSphere / ESXi)` — Hyperviseurs hebergeant l'ensemble des VMs (DC, SIEM, Veeam, fichiers). Compromission de vCenter/ESXi = chiffrement de toutes les VMs en un 
- **Pieds-à-terre probables (origine d'attaque)** :
  - bx-dev-* (classe la plus volumineuse ~13.6M evts : postes/VMs dev, bx-dev-tca1/2/3-pc, bx-dev-dell1/2-pc, bx-dev-seal-vm, bx-dev-repo-vm — droits larg
  - bx-qa-* (~8.2M : bancs QA bx-qa-seal-vm, bx-qa-rle-lt, bx-qa-test-vm — souvent peu durcis)
  - bx-com/bx-comm-* (~5.1M : commerciaux bx-com-jma-lt2, bx-com-vle-lt2 — exposes phishing, nomades)
  - bx-dom-user1..4-lt (postes utilisateurs standards generiques — population large et homogene)
  - iv-tech-* / in-dev-* (~3.8M : site secondaire, postes techniciens nomades, surface laterale inter-sites)

## Comptes AD leurres (type `identity`)

### `svc_veeam`  ·  clé lookup = `svc_veeam`
- **Se fond comme** : Compte de service AD pour l'infra de sauvegarde Veeam (pattern svc_ underscore dominant, comme svc_siem/svc_intranet). Nom hautement allechant : un compte 'service backup' implique des droits etendus sur les serveurs et 
- **Chemin d'attaque intercepté** : Kerberoasting / recon de comptes service -> l'attaquant enumere les SPN ou liste les comptes svc_* depuis un foothold (bx-dev-*, bx-qa-*), repere 'svc_veeam' comme passerelle vers l'infra de sauvegarde Veeam (bx-veeam-it-sv, bx-veeam-prx1/2) et tente un TGS-RE
- **Se déclenche sur** : Tout 4768 (AS-REQ/TGT) ou 4769 (TGS-REQ) ou 4624/4625 ou que winlogbeat_winlog_event_data_TargetUserName == 'svc_veeam' (4768) ou winlogbeat_winlog_event_data_ServiceName == 'svc_veeam' (4769). La reg
- **Comment le planter (dry-run)** : Julien cree le compte en DRY-RUN sur l'AD OMNITECH.SECURITY (jamais le tenant co-manage invissys.com) : New-ADUser -WhatIf 'svc_veeam' dans une OU de comptes de service, mot de passe long aleatoire jamais distribue, lui attacher un SPN attractif (ex setspn -A VEEAM/bx-veeam-it-sv svc_veeam) pour qu'il soit kerberoastab

### `svc_sql`  ·  clé lookup = `svc_sql`
- **Se fond comme** : Compte de service AD pour une base SQL applicative (pattern svc_ underscore). Se fond aux cotes du reel Omnitech-SSRS (SQL Server Reporting Services) et de bx-files-it-vm : un 'svc_sql' est exactement ce qu'un attaquant 
- **Chemin d'attaque intercepté** : Kerberoasting d'un compte service SQL classique (les svc SQL ont souvent des mots de passe faibles et un SPN MSSQLSvc). L'attaquant casse le ticket offline puis vise les donnees metier de bx-files-it-vm / la base SSRS (Omnitech-SSRS) pour exfiltration ou chiff
- **Se déclenche sur** : 4769 avec winlogbeat_winlog_event_data_ServiceName == 'svc_sql' (TGS demande, signature kerberoasting), ou 4768 avec winlogbeat_winlog_event_data_TargetUserName == 'svc_sql', ou 4625/4624. Match via l
- **Comment le planter (dry-run)** : DRY-RUN sur l'AD OMNITECH uniquement : New-ADUser -WhatIf 'svc_sql' avec SPN MSSQLSvc/bx-sql-it-vm:1433 (setspn -A ...), description 'SQL Server service account', mot de passe robuste jamais utilise, refus de logon interactif. Aucun service SQL reel ne tourne sous ce compte. Ajout cle 'svc_sql' -> 'ad_account' au CSV o

### `svc_backup`  ·  clé lookup = `svc_backup`
- **Se fond comme** : Compte de service AD 'sauvegarde' generique (pattern svc_ underscore dominant). Nom universellement allechant : un attaquant suppose qu'un 'svc_backup' detient des droits de lecture larges (souvent operateur de sauvegard
- **Chemin d'attaque intercepté** : Recon de comptes a fort privilege -> abus du groupe Backup Operators (lecture brute des fichiers proteges, voire SeBackupPrivilege pour dumper SAM/NTDS.dit). Chemin vers DCSync / extraction de la base AD des DC (bx-ad-01-it-vm, bx-ad02-it-vm) ou vers le serveu
- **Se déclenche sur** : 4768 (TGT) ou 4769 (TGS) ou 4624 (logon) ou 4672 (privileges speciaux assignes) avec winlogbeat_winlog_event_data_TargetUserName == 'svc_backup' (ou _ServiceName en 4769). lookup_value('omni-deception
- **Comment le planter (dry-run)** : DRY-RUN AD OMNITECH : New-ADUser -WhatIf 'svc_backup', l'ajouter NOMINALEMENT (en dry-run/-WhatIf) comme membre leurre d'un groupe a consonance privilegiee (ex un faux groupe 'Backup Operators Svc'), description 'Service de sauvegarde planifiee', credentials jamais distribuees, logon interactif refuse. Cle 'svc_backup'

### `adm-sql`  ·  clé lookup = `adm-sql`
- **Se fond comme** : Compte d'administration delegue (pattern adm- dominant : adm-jmorin, adm-aculleron, adm-retevenard...). 'adm-sql' se lit comme l'admin attitre des bases SQL — cible directe pour quiconque cherche a controler le tier donn
- **Chemin d'attaque intercepté** : Apres compromission d'un poste, l'attaquant enumere les comptes adm-* (privilegies) et cible 'adm-sql' pour rebondir vers les serveurs SQL / SSRS (Omnitech-SSRS) et bx-files-it-vm. Toute tentative d'auth ou de Kerberos sur ce compte = mouvement lateral vers le
- **Se déclenche sur** : 4768/4769/4624/4625 avec winlogbeat_winlog_event_data_TargetUserName == 'adm-sql'. Toute apparition est anormale (compte jamais utilise). Match lookup omni-deception == 'ad_account'.
- **Comment le planter (dry-run)** : DRY-RUN sur AD OMNITECH : New-ADUser -WhatIf 'adm-sql' dans l'OU des comptes d'admin delegues, description 'Admin SQL delegue', l'inscrire (dry-run) comme membre nominal d'un groupe privilegie leurre, mot de passe fort jamais communique, deny interactive logon. Ajout 'adm-sql' -> 'ad_account' au CSV omni-deception. Jam

### `adm-backup`  ·  clé lookup = `adm-backup`
- **Se fond comme** : Compte admin delegue 'sauvegarde' (pattern adm- dominant). Combine l'attrait du privilege admin et du domaine backup/restauration : exactement le compte qu'un operateur de ransomware veut pour neutraliser Veeam avant chi
- **Chemin d'attaque intercepté** : Recon des comptes adm-* a privileges -> 'adm-backup' presume membre d'un groupe a droits etendus sur l'infra Veeam (bx-veeam-it-sv, bx-veeam-prx1/2) et/ou Backup Operators. Chemin ransomware : detruire les sauvegardes pour maximiser le levier d'extorsion (joya
- **Se déclenche sur** : 4768 (TGT) / 4769 (TGS) / 4624 / 4672 avec winlogbeat_winlog_event_data_TargetUserName == 'adm-backup'. lookup_value('omni-deception', to_lower(<champ>)) == 'ad_account'.
- **Comment le planter (dry-run)** : DRY-RUN AD OMNITECH uniquement : New-ADUser -WhatIf 'adm-backup', description 'Admin sauvegarde Veeam', membre nominal (dry-run) d'un groupe privilegie leurre, password aleatoire non distribue, logon interactif refuse, jamais associe a un service vivant. Cle 'adm-backup' -> 'ad_account' au CSV. Hors invissys.com.

### `BX-SQL-IT-VM$`  ·  clé lookup = `bx-sql-it-vm$`
- **Se fond comme** : Compte MACHINE d'un faux serveur SQL respectant la nomenclature crown-jewel (site bx + segment -it- + suffixe -vm + majuscules + '$', comme BX-FILES-IT-VM$, BX-VEEAM-IT-SV$, BX-AD-01-IT-VM$). Se fond parfaitement dans le
- **Chemin d'attaque intercepté** : Reconnaissance laterale / scan AD : l'attaquant resout les noms de serveurs -it-vm crown-jewel et tente une auth Kerberos contre le compte machine BX-SQL-IT-VM$ (serveur SQL imaginaire), revelant son intention de pivoter vers le tier base de donnees (donnees m
- **Se déclenche sur** : 4768 (AS-REQ d'un compte machine) ou 4769 ou 4624 avec winlogbeat_winlog_event_data_TargetUserName == 'BX-SQL-IT-VM$' (to_lower -> 'bx-sql-it-vm$'). Aucun hote reel ne s'authentifie ainsi, donc tout h
- **Comment le planter (dry-run)** : DRY-RUN AD OMNITECH : New-ADComputer -WhatIf 'BX-SQL-IT-VM' (objet ordinateur leurre, aucun hote physique/VM derriere), enregistrement DNS leurre optionnel bx-sql-it-vm.omnitech-security.fr pointant vers un puits/IP non routee, aucun service ecoute. Ajout cle 'bx-sql-it-vm$' (minuscule) -> 'ad_account' au CSV omni-dece

## Comptes-SPN Kerberoast leurres (type `identity`, détectés via TGS 4769)

### `svc_sql (faux compte de service SQL avec SPN MSSQLSvc weak/RC4)`  ·  clé lookup = `svc_sql`
- **Se fond comme** : Compte de service applicatif AD nomme selon le pattern dominant 'svc_<service>' (cf svc_siem, svc_intranet). Il porte un SPN MSSQLSvc/bx-sql-it-vm.omnitech-security.fr:1433 evoquant une instance SQL metier, cohérent avec
- **Chemin d'attaque intercepté** : Apres foothold sur bx-dev-* / bx-qa-*, l'attaquant lance un Kerberoast (Rubeus kerberoast / GetUserSPNs.py / Invoke-Kerberoast) pour enumerer tous les comptes SPN et demande un TGS RC4 crackable hors-ligne, visant les bases SQL metier (bx-files-it-vm, SSRS) pu
- **Se déclenche sur** : EID 4769 (Kerberos Service Ticket Operations) ou winlogbeat_winlog_event_id=4769 avec winlogbeat_winlog_event_data_ServiceName='svc_sql' (sAMAccountName du compte porteur du SPN) ; signal renforce par
- **Comment le planter (dry-run)** : En DRY-RUN sur l'AD OMNITECH.SECURITY (DC bx-ad-01-it-vm), Julien cree un objet utilisateur desactive 'svc_sql' (Enabled=$false), pose setspn -S MSSQLSvc/bx-sql-it-vm.omnitech-security.fr:1433 svc_sql et MSSQLSvc/bx-sql-it-vm:1433, force msDS-SupportedEncryptionTypes=4 (RC4 uniquement), met un mot de passe long aleatoi

### `svc_veeam (faux compte de service de sauvegarde Veeam SPN-roastable)`  ·  clé lookup = `svc_veeam`
- **Se fond comme** : Compte 'svc_veeam' suivant le pattern svc_ underscore, calque sur l'infra de sauvegarde reelle (bx-veeam-it-sv, BX-VEEAM-IT-SV$, bx-veeam-prx*). SPN factice VeeamBackupSvc/bx-veeam-it-sv.omnitech-security.fr et HTTP/bx-v
- **Chemin d'attaque intercepté** : Operateur ransomware cherchant a detruire les sauvegardes : il Kerberoast le compte 'svc_veeam' pour casser son mot de passe et acceder a la console/repository Veeam (bx-veeam-it-sv) afin de supprimer/chiffrer les backups avant deploiement du chiffrement, maxi
- **Se déclenche sur** : EID 4769 avec winlogbeat_winlog_event_data_ServiceName='svc_veeam' ; tout TGS demande sur ce compte (a fortiori en RC4 0x17) = enumeration Kerberoast, car le compte n'a aucune charge de travail legiti
- **Comment le planter (dry-run)** : Dry-run sur DC OMNITECH.SECURITY : creer utilisateur desactive 'svc_veeam' (jamais sur invissys.com), setspn -S VeeamBackupSvc/bx-veeam-it-sv.omnitech-security.fr svc_veeam et HTTP/bx-veeam-it-sv, forcer RC4 via msDS-SupportedEncryptionTypes=4, mot de passe fort + PasswordLastSet ancien, description 'Veeam service acco

### `svc_backup (faux compte de service de sauvegarde generique a SPN faible)`  ·  clé lookup = `svc_backup`
- **Se fond comme** : Compte 'svc_backup' au nom generique tres credible (recommandation directe de la carte d'env), pattern svc_ dominant. Porte un SPN HTTP/bx-backup2-it-vm.omnitech-security.fr et cifs/bx-backup2-it-vm, suggerant un hote de
- **Chemin d'attaque intercepté** : Reconnaissance laterale post-foothold : l'attaquant Kerberoast l'ensemble du domaine, repere 'svc_backup' (nom evocateur de droits larges sur le stockage), crack le ticket et tente l'acces aux partages/serveur de sauvegarde, pivot vers bx-files-it-vm et l'infr
- **Se déclenche sur** : EID 4769 avec winlogbeat_winlog_event_data_ServiceName='svc_backup' ; declenchement au premier TGS sollicite (Kerberoast), independamment du type de chiffrement, le compte etant inerte par constructio
- **Comment le planter (dry-run)** : Dry-run AD OMNITECH.SECURITY : utilisateur desactive 'svc_backup', setspn -S HTTP/bx-backup2-it-vm.omnitech-security.fr svc_backup + cifs/bx-backup2-it-vm (l'hote bx-backup2-it-vm n'existe pas = double leurre), encryption RC4 only, mot de passe robuste avec PasswordLastSet recule de 2-3 ans, OU=Honey. CSV omni-deceptio

### `svc_scan (faux compte de service scanner/MFP a SPN HTTP roastable)`  ·  clé lookup = `svc_scan`
- **Se fond comme** : Compte 'svc_scan' typique des comptes scan-to-folder / MFP (recommande par la carte d'env), pattern svc_ underscore. SPN HTTP/bx-scan-it-vm.omnitech-security.fr, profil 'compte de service a mot de passe jamais change' ->
- **Chemin d'attaque intercepté** : Apres compromission d'un poste utilisateur standard (bx-dom-user*-lt) ou commercial (bx-com-*), l'attaquant Kerberoast et selectionne 'svc_scan' comme cible facile (comptes scan = mots de passe historiquement faibles et reutilises), cherchant a rebondir vers d
- **Se déclenche sur** : EID 4769 avec winlogbeat_winlog_event_data_ServiceName='svc_scan' ; tout TGS sur ce compte signe l'enumeration SPN, signal accru si TicketEncryptionType=0x17 (RC4).
- **Comment le planter (dry-run)** : Dry-run sur DC OMNITECH.SECURITY uniquement : creer 'svc_scan' desactive, setspn -S HTTP/bx-scan-it-vm.omnitech-security.fr svc_scan, forcer RC4 (msDS-SupportedEncryptionTypes=4), mot de passe fort + PasswordLastSet ancien, description 'Scan to folder service', OU leurre. Inserer svc_scan->kerberoast_spns dans le CSV o

### `svc_sap (faux compte de service applicatif ERP a SPN attractif)`  ·  clé lookup = `svc_sap`
- **Se fond comme** : Compte 'svc_sap' simulant un service d'integration ERP/applicatif (coherent avec les comptes applicatifs observes type intranet/owncloud), pattern svc_ dominant. SPN HTTP/bx-erp-it-vm.omnitech-security.fr et MSSQLSvc/bx-
- **Chemin d'attaque intercepté** : L'attaquant vise les donnees metier : il Kerberoast 'svc_sap', concu pour evoquer un compte ERP a fort privilege applicatif et a base SQL adjacente, crack le secret hors-ligne et tente l'acces aux donnees metier centralisees (exfiltration) puis l'escalade via 
- **Se déclenche sur** : EID 4769 avec winlogbeat_winlog_event_data_ServiceName='svc_sap' ; premier TGS demande = Kerberoast, le compte n'ayant aucune session de service legitime.
- **Comment le planter (dry-run)** : Dry-run sur AD OMNITECH.SECURITY : utilisateur desactive 'svc_sap', setspn -S HTTP/bx-erp-it-vm.omnitech-security.fr svc_sap + MSSQLSvc/bx-erp-it-vm.omnitech-security.fr:1433, encryption RC4 only, mot de passe long aleatoire, PasswordLastSet recule, OU=Honey, description 'ERP integration service'. CSV omni-deception : 

### `svc-fortiweb (faux compte service tiret simulant integration Fortinet)`  ·  clé lookup = `svc-fortiweb`
- **Se fond comme** : Compte 'svc-fortiweb' utilisant la variante MINORITAIRE 'svc-' (tiret) reellement observee (svc-fortimanager) pour couvrir les deux conventions de nommage et pieger un attaquant qui enumere large. SPN HTTP/bx-fortiweb-it
- **Chemin d'attaque intercepté** : Apres pivot inter-sites (iv-tech-*/in-dev-*) ou compromission perimetrique, l'attaquant Kerberoast le domaine et cible 'svc-fortiweb' (comptes d'integration appliance souvent a privileges et mal durcis), casse le ticket et tente d'atteindre la console/admin de
- **Se déclenche sur** : EID 4769 avec winlogbeat_winlog_event_data_ServiceName='svc-fortiweb' ; tout TGS sollicite revele l'enumeration SPN, FP structurellement nul car aucun service legitime n'emploie ce compte.
- **Comment le planter (dry-run)** : Dry-run AD OMNITECH.SECURITY : creer 'svc-fortiweb' desactive (variante tiret deliberee), setspn -S HTTP/bx-fortiweb-it-vm.omnitech-security.fr svc-fortiweb, forcer RC4, mot de passe robuste + PasswordLastSet ancien, OU leurre, description 'Fortinet LDAP integration'. Ajouter svc-fortiweb->kerberoast_spns au CSV omni-d

## Tokens canari (type `canary`)

### `Canary DNS - sous-domaine "backup vault" embarque dans un KeePass appat`  ·  clé lookup = `kdbx-restore.bkp-omnitech-vault.net`
- **Se fond comme** : Une URL de "restauration de coffre" stockee comme champ URL/Note dans un fichier KeePass nomme 'Sauvegardes-Infra.kdbx' (entree 'svc_backup - restore portal', cf pattern svc_ dominant). Le sous-domaine ressemble a un por
- **Chemin d'attaque intercepté** : Foothold sur bx-dev-* / bx-qa-* -> ramassage de fichiers .kdbx sur partages SMB / postes -> ouverture du KeePass appat (souvent faible passphrase ou keyfile a cote) -> l'attaquant suit l'URL 'restore portal' pensant atteindre l'infra de sauvegarde Veeam (joyau
- **Se déclenche sur** : event_source=fortigate, champ qname (ou hostname) == 'kdbx-restore.bkp-omnitech-vault.net' -> regle lookup_value('omni-deception', to_lower(qname)) == 'canary'. Tout contact (resolution DNS ou connexi
- **Comment le planter (dry-run)** : DRY-RUN sur l'AD/infra OMNITECH uniquement. Julien (1) enregistre/pointe le sous-domaine sentinelle sur un collecteur canary externe (Canarytokens/DNS sinkhole), (2) cree le .kdbx appat sur un poste de staging bx-dev (PAS de creation de compte AD reel), (3) en dry-run depose une copie en lecture seule sur un partage SM

### `Canary DNS - profil VPN appat (.ovpn) avec endpoint leurre`  ·  clé lookup = `gw-remote.vpn-omnitech-secure.net`
- **Se fond comme** : Un fichier de configuration VPN 'OMNITECH-VPN-Teletravail.ovpn' (ou .rdp / profil FortiClient) ou la directive 'remote' pointe vers ce hostname de passerelle. Imite la convention d'une gateway d'acces distant nomade (pop
- **Chemin d'attaque intercepté** : Compromission d'un laptop nomade bx-com-* / bx-adv-* (expose phishing) -> recuperation de configs VPN locales pour pivoter vers le reseau interne / atteindre les DC et le serveur de fichiers -> l'attaquant tente de se connecter a la passerelle 'gw-remote' du .
- **Se déclenche sur** : event_source=fortigate, qname/hostname == 'gw-remote.vpn-omnitech-secure.net'. La regle lookup_value('omni-deception', to_lower(hostname)) == 'canary' tire au premier paquet DNS/TLS. Zero usage legiti
- **Comment le planter (dry-run)** : DRY-RUN sur infra OMNITECH. Julien (1) fait pointer le sous-domaine sentinelle sur le collecteur canary externe, (2) genere un .ovpn factice (certs auto-signes bidons, pas de PKI reelle bx-pki2022), (3) en dry-run le place dans un dossier 'Acces-Distant' d'un poste bait bx-adv de staging et/ou en piece jointe d'un faux

### `Canary SSH - cle privee appat avec hostname cible en commentaire/known_hosts`  ·  clé lookup = `git-deploy.repo-omnitech-ci.net`
- **Se fond comme** : Une cle SSH privee 'id_rsa_deploy' + un known_hosts/config SSH ou le Host pointe vers 'git-deploy.repo-omnitech-ci.net' (faux serveur CI/CD de deploiement, coherent avec la classe dev tres volumineuse bx-dev-repo-vm). Le
- **Chemin d'attaque intercepté** : Foothold sur bx-dev-* (cible initiale ideale, droits larges, outils dev) -> moisson de ~/.ssh/ -> l'attaquant utilise la cle pour atteindre le 'serveur de deploiement' git-deploy, esperant pivoter vers les depots et l'infra CI (chemin vers code source / secret
- **Se déclenche sur** : event_source=fortigate, qname/hostname == 'git-deploy.repo-omnitech-ci.net' (resolution DNS lors du ssh) -> lookup_value('omni-deception', to_lower(qname)) == 'canary'. Optionnellement double couvertu
- **Comment le planter (dry-run)** : DRY-RUN sur AD/infra OMNITECH. Julien (1) pointe le sous-domaine sur le sinkhole/collecteur canary, (2) genere une paire de cles jetable hors de toute infra reelle, (3) en dry-run depose id_rsa_deploy + ~/.ssh/config (Host git-deploy ...) sur un poste de staging bx-dev, jamais sur bx-dev-repo-vm reel, (4) ajoute la cle

### `Canary Office - document Word appat a image distante (web bug) vers sous-domaine canari`  ·  clé lookup = `assets.dr-omnitech-plan.net`
- **Se fond comme** : Un document 'PLAN-REPRISE-ACTIVITE-2026-CONFIDENTIEL.docx' (ou .xlsx 'Mots_de_passe_Admin') contenant une image/lien distant (web bug) charge depuis 'assets.dr-omnitech-plan.net'. Se fond comme un doc DR/PRA hautement at
- **Chemin d'attaque intercepté** : Apres foothold (bx-dev / bx-qa / bx-dom-user*), l'attaquant chasse les documents sensibles sur les partages SMB du serveur de fichiers (joyau bx-files-it-vm). L'ouverture du PRA appat pour reperer les procedures/credentials d'urgence declenche le chargement de
- **Se déclenche sur** : event_source=fortigate, qname/hostname == 'assets.dr-omnitech-plan.net' (charge a l'ouverture du document) -> lookup_value('omni-deception', to_lower(hostname)) == 'canary'. L'evenement exact = la req
- **Comment le planter (dry-run)** : DRY-RUN sur infra OMNITECH. Julien (1) heberge un 1x1 pixel sur le collecteur canary et pointe le sous-domaine dessus, (2) fabrique le .docx avec lien d'image externe (Canarytoken Word), (3) en dry-run le place sur un partage SMB de staging avec un nom alléchant et un ACL volontairement permissif/decouvrable, jamais su

### `Canary AD - faux compte service Kerberoastable a SPN leurre (TGS canari)`  ·  clé lookup = `mssqlsvc/sql-omnitech-rpt.omnitech.security`
- **Se fond comme** : Un compte de service AD desactive 'svc_sqlrpt' (pattern svc_ underscore dominant) portant un SPN attractif type service SQL Reporting (echo a Omnitech-SSRS reel sans le copier). Mot de passe volontairement faible/crackab
- **Chemin d'attaque intercepté** : Foothold avec n'importe quel compte de domaine -> enumeration des SPN (GetUserSPNs/Rubeus) pour Kerberoasting -> l'attaquant demande un ticket TGS (EID 4769) pour ce SPN leurre afin de cracker hors-ligne le secret du 'compte SQL'. Intercepte la phase d'escalad
- **Se déclenche sur** : event_source=windows_security, winlogbeat_winlog_event_id=4769, winlogbeat_winlog_event_data_ServiceName correspondant au compte leurre (svc_sqlrpt) -> lookup_value('omni-deception', to_lower(winlogbe
- **Comment le planter (dry-run)** : DRY-RUN sur l'AD OMNITECH.SECURITY. Julien (1) en dry-run prepare la creation d'un compte svc_sqlrpt DESACTIVE avec SPN setspn 'MSSQLSvc/sql-omnitech-rpt.omnitech.security' (objet AD leurre, jamais membre d'un groupe a vrai pouvoir), nom inexistant donc zero collision, (2) renseigne le CSV omni-deception en minuscule a

### `Canary partage - raccourci .lnk "lecteur reseau" appat declenchant un beacon SMB/DNS`  ·  clé lookup = `fs-archive.share-omnitech-fin.net`
- **Se fond comme** : Un raccourci 'Comptabilite (Z).lnk' ou un fichier desktop.ini/icone pointant vers \\fs-archive.share-omnitech-fin.net\compta -> imite un mappage de lecteur reseau finance (segment compta/cmpta credible, suffixe coherent)
- **Chemin d'attaque intercepté** : Foothold + recon des lecteurs reseaux et raccourcis pour localiser les partages finance/compta sensibles -> l'attaquant tente d'atteindre le 'serveur d'archive comptable' fs-archive (chemin vers donnees metier sensibles, exfiltration, et vers le serveur de fic
- **Se déclenche sur** : event_source=fortigate, qname/hostname == 'fs-archive.share-omnitech-fin.net' (resolution DNS lors de la tentative d'acces SMB / render d'icone du .lnk) -> lookup_value('omni-deception', to_lower(qnam
- **Comment le planter (dry-run)** : DRY-RUN sur infra OMNITECH. Julien (1) pointe le sous-domaine sentinelle sur le sinkhole/collecteur canary (l'hote SMB n'existe pas, seule la resolution suffit a tirer), (2) fabrique le .lnk appat (Canarytoken Windows folder/UNC), (3) en dry-run le depose sur un partage de staging et/ou un poste bait bx-dom-user avec u

## Hôtes leurres → comptes MACHINE (type `identity`)

### `bx-sql-it-vm`  ·  clé lookup = `bx-sql-it-vm$`
- **Se fond comme** : Serveur SQL applicatif de production a Bordeaux (segment crown-jewel '-it-', suffixe '-vm'), pendant credible du reel Omnitech-SSRS/bx-files-it-vm. Aucune base SQL nommee ainsi n'existe = aucun trafic legitime.
- **Chemin d'attaque intercepté** : Recon laterale vers les donnees metier : un attaquant ayant pivote (bx-dev-*/bx-qa-*) enumere les serveurs juteux et tente Kerberoasting/auth sur ce 'serveur SQL'. Intercepte le chemin vers bx-files-it-vm + Omnitech-SSRS (exfiltration/chiffrement de la base ap
- **Se déclenche sur** : Tout EID 4768 (TGT) ou 4769 (TGS/Kerberoast) ou 4624/4625 ou DNS query ou la cle 'bx-sql-it-vm$' (TargetUserName/ServiceName) apparait dans la telemetrie ; lookup_value('omni-deception', to_lower(winl
- **Comment le planter (dry-run)** : En DRY-RUN sur l'AD OMNITECH.SECURITY uniquement (jamais le tenant co-manage invissys.com) : Julien cree un objet ordinateur desactive BX-SQL-IT-VM dans l'OU serveurs (New-ADComputer -Enabled $false en -WhatIf d'abord), lui attache un SPN attractif (MSSQLSvc/bx-sql-it-vm.omnitech-security.fr:1433) et publie l'enregistr

### `bx-backup2-it-vm`  ·  clé lookup = `bx-backup2-it-vm$`
- **Se fond comme** : Second serveur de sauvegarde Bordeaux (convention '-it-vm'), suite logique credible de bx-veeam-it-sv. Numerotation '2' coherente avec le parc (bx-ad02, bx-veeam-prx2). Aucun service reel = contact = recon.
- **Chemin d'attaque intercepté** : Cible ransomware prioritaire : neutralisation des sauvegardes avant chiffrement. Intercepte le chemin vers bx-veeam-it-sv + bx-veeam-prx1/prx2 (destruction de la capacite de restauration, levier d'extorsion).
- **Se déclenche sur** : Tout 4768/4769/4624/4625 ciblant le compte machine 'bx-backup2-it-vm$', ou resolution DNS/connexion SMB/RDP vers cet hote ; regle lookup_value('omni-deception', to_lower(<TargetUserName|ServiceName>))
- **Comment le planter (dry-run)** : DRY-RUN AD OMNITECH uniquement (PAS invissys.com) : compte ordinateur desactive BX-BACKUP2-IT-VM cree via New-ADComputer -WhatIf puis -Enabled $false, SPN HOST/bx-backup2-it-vm + enregistrement DNS A leurre pointant sur une IP non routee/blackhole. Reference dans omni-deception : 'bx-backup2-it-vm$' -> 'decoy_host'.

### `bx-pki2025-it-vm`  ·  clé lookup = `bx-pki2025-it-vm$`
- **Se fond comme** : Nouvelle autorite de certification ADCS (millesime 2025), pendant credible et 'plus recent' du reel bx-pki2022. Le millesime dans le nom suit la convention observee (bx-pki2022). Aucune CA reelle = tout contact suspect.
- **Chemin d'attaque intercepté** : Abus de gabarits de certificats (ESC1-8) pour persistance/usurpation a l'echelle du domaine. Un attaquant qui enumere les CA (certutil, Certify) frappera cette 'nouvelle PKI' avant la vraie. Intercepte le chemin vers bx-pki2022/ADCS et l'escalade domaine.
- **Se déclenche sur** : Tout 4768/4769 vers 'bx-pki2025-it-vm$', toute requete DNS/LDAP/enrollment vers cet hote, ou apparition de la cle dans la telemetrie ; lookup_value('omni-deception', to_lower(<champ>)) == 'decoy_host'
- **Comment le planter (dry-run)** : DRY-RUN AD OMNITECH (jamais invissys.com) : objet ordinateur desactive BX-PKI2025-IT-VM (New-ADComputer -WhatIf), SPN HOST + enregistrement DNS leurre ; ne PAS installer de role ADCS reel ni publier de gabarit (leurre passif). Optionnel : faux objet pKIEnrollmentService dans la config partition en lab isole seulement. 

### `bx-fs02-it-vm`  ·  clé lookup = `bx-fs02-it-vm$`
- **Se fond comme** : Second serveur de fichiers Bordeaux (abreviation 'fs' + numerotation '02' coherente avec bx-ad02), pendant credible du reel bx-files-it-vm. Partages SMB sensibles supposes. Aucun partage reel = tout acces = attaquant.
- **Chemin d'attaque intercepté** : Exfiltration/chiffrement de donnees metier : enumeration de partages SMB (net view, SharpShares) et acces au 'serveur de fichiers'. Intercepte le chemin vers bx-files-it-vm (donnees metier centralisees).
- **Se déclenche sur** : Tout 4768/4769/4624 ciblant 'bx-fs02-it-vm$', toute tentative SMB/connexion vers l'hote, ou apparition de la cle ; lookup_value('omni-deception', to_lower(<TargetUserName|ServiceName>)) == 'decoy_host
- **Comment le planter (dry-run)** : DRY-RUN AD OMNITECH uniquement (jamais le tenant co-manage invissys.com) : compte ordinateur desactive BX-FS02-IT-VM cree en -WhatIf puis -Enabled $false, SPN cifs/bx-fs02-it-vm.omnitech-security.fr + enregistrement DNS A leurre, aucun partage reel monte. Cle omni-deception 'bx-fs02-it-vm$' -> 'decoy_host'.

### `bx-esxi-05-it`  ·  clé lookup = `bx-esxi-05-it$`
- **Se fond comme** : Cinquieme hote ESXi Bordeaux, suite directe et credible de bx-esxi-01..04-it (positifs reels confirmes en telemetrie). Convention exacte (segment '-it', pas de suffixe -vm car bare-metal). Aucun hyperviseur reel '05' = t
- **Chemin d'attaque intercepté** : Ransomware ESXi / contournement securite invitee : un attaquant qui compromet vCenter enumere les hotes ESXi pour chiffrer toutes les VMs en un point. Intercepte le chemin vers vcenter + bx-esxi-01..04-it (chiffrement global DC/SIEM/Veeam/fichiers).
- **Se déclenche sur** : Tout 4768/4769 vers 'bx-esxi-05-it$', toute requete DNS/connexion (443/902/SSH) vers l'hote, ou apparition de la cle dans les logs vsphere/security ; lookup_value('omni-deception', to_lower(<champ>)) 
- **Comment le planter (dry-run)** : DRY-RUN AD/infra OMNITECH uniquement (jamais invissys.com) : objet ordinateur desactive BX-ESXI-05-IT (New-ADComputer -WhatIf), enregistrement DNS A leurre bx-esxi-05-it.omnitech-security.fr, et optionnellement un faux hote inventorie dans vCenter en mode deconnecte (lab/dry-run). Aucun ESXi reel deploye. Cle omni-dece

### `bx-ad03-it-vm`  ·  clé lookup = `bx-ad03-it-vm$`
- **Se fond comme** : Troisieme controleur de domaine Bordeaux, suite directe et hautement credible de bx-ad-01/bx-ad02-it-vm (DC reels, emetteurs 4768). La numerotation '03' est la convention exacte. Aucun DC reel '03' = toute auth = attaque
- **Chemin d'attaque intercepté** : Cible n1 de toute intrusion AD : un attaquant cherche les DC pour DCSync/Golden Ticket/replication. Tout contact avec ce 'DC' (DRSUAPI, LDAP, auth machine) revele une compromission domaine en cours. Intercepte le chemin vers bx-ad-01/bx-ad02-it-vm + vm-paca-ad
- **Se déclenche sur** : Tout 4768/4769/4624 ciblant 'bx-ad03-it-vm$', toute requete LDAP/DNS SRV/DRSUAPI vers l'hote, ou apparition de la cle ; lookup_value('omni-deception', to_lower(<TargetUserName|ServiceName>)) == 'decoy
- **Comment le planter (dry-run)** : DRY-RUN AD OMNITECH uniquement (jamais invissys.com) : compte ordinateur desactive BX-AD03-IT-VM (New-ADComputer -WhatIf, JAMAIS promu DC reel), SPN leurre + enregistrement DNS A. Ne PAS l'ajouter au groupe Domain Controllers ni publier de SRV _ldap reel (leurre passif strict). Cle omni-deception 'bx-ad03-it-vm$' -> 'd

## Activation

Les clés ci-dessus sont **déjà dans le registre** `lookups/deception-decoys.csv` et résolues
par le lookup `omni-deception` (vérifié : `svc_veeam`→identity, `BX-AD03-IT-VM$`→identity,
`kdbx-restore.bkp-omnitech-vault.net`→canary, `jmorin`→null). **Dès que tu plantes un appât**,
le piège correspondant tire à fidélité ~100 % (mail + Teams SOC, priorité haute).

> **Canaris** : les FQDN sont des domaines **externes disjoints de la zone AD** (choix de
> conception, pour éviter l'auto-résolution par les scanners AD). La détection se fait sur la
> **requête DNS sortante** (Sysmon EID22 / FortiGate) — elle fonctionne même si le domaine
> n'est pas enregistré. Pour une alerte *out-of-band* en plus, enregistrer le token sur un
> service type Canarytokens (optionnel).

