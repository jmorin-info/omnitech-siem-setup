# Backlog de détection — lacunes MITRE ATT&CK

> Généré par workflow multi-agents (audit couverture vs 132 détections + sources OMNITECH).
> 65 candidats → **47 confirmés** (réellement non couverts + faisables) → **42** priorisés ci-dessous.

**Synthèse :** Le theme dominant est l'identite cloud M365/Entra : la majorite des angles morts a haute valeur portent sur la persistance et le credential-access cloud (federation/Golden SAML, methodes MFA, legacy auth bypass-MFA, MFA-fatigue, device registration, desactivation de l'Unified Audit Log), surface critique car OMNITECH depend fortement de M365 sans CASB/DLP/EDR. Le second bloc majeur est comportemental cote endpoint via Sysmon (execution navigateur/PDF/archiveur, decouverte AV/annuaire/systeme, RDP single-hop, PtH/PtT, C2 par RMM/tunneling/SaaS) : telemetrie deja collectee mais jamais exploitee en detection, faute d'EDR/NDR. Les vecteurs physiques (USB) et certains canaux DNS exigent d'abord un prerequis (sous-categories d'audit GPO PnP/Removable Storage, canal Sysmon EID22 plutot que le DNS-DC Audit qui ne porte pas les requetes). Le piege transversal recurrent est l'echec silencieux : presque toutes les requetes proposees utilisent de faux noms de champs (winlogbeat_event_data_* au lieu de winlogbeat_winlog_event_data_*, m365_operation/m365_workload au lieu de event_action, srcintf:wan1 au lieu de srcintfrole:wan, service au lieu de dest_port) ou des filtres trop larges generateurs de flood, imposant correction du schema, allowlists (81-fp-allowlist) et baseline avant tout deploiement.

⚠️ Chaque requête est une PROPOSITION : valider les noms de champs et le risque FP sur données réelles avant mise en prod.

## #1 · T1133 — External Remote Services (login SSL-VPN reussi depuis IP malveillante/Tor)
- **Tactique** : Initial Access (TA0001)  ·  **Priorité** : haute
- **Source** : FortiGate VPN (champ remip) + lookup threat-intel Feodo/Tor/Spamhaus
- **Requête** : `subtype:vpn AND (action:ssl\-login OR action:tunnel\-up) AND remip_threat_indicated:true`
- **Justification** : FP faible. Gap propre: les 3 detections VPN existantes sont geo ou echec, jamais reputation sur remip. Prereq: ajouter regle pipeline omni-forti-10-threatintel-remip set_fields(threat_intel_lookup_ip(remip,"remip")). NE PAS utiliser remip_threat_intel:* (champ inexistant).

## #2 · T1606.002 — Forge Web Credentials: SAML Tokens (Golden SAML / federation hijack)
- **Tactique** : Credential Access (TA0006)  ·  **Priorité** : haute
- **Source** : M365 Management Activity / Entra audit (Audit.AzureActiveDirectory)
- **Requête** : `event_source:m365 AND m365_workload:AzureActiveDirectory AND event_action:("Set federation settings on domain" OR "Set domain authentication" OR "Add unverified domain")`
- **Justification** : FP faible. Compromission totale de tenant, volume quasi nul en regime etabli (PME sans ADFS). RETIRER 'Add service principal credentials' (autre TTP, bruyant). Enrichir acteur+IP.

## #3 · T1621 — Multi-Factor Authentication Request Generation (MFA fatigue / push bombing)
- **Tactique** : Credential Access (TA0006)  ·  **Priorité** : haute
- **Source** : M365 / Entra sign-in logs
- **Requête** : `event_source:m365 AND m365_type:signin AND m365_fail_code:500121 | groupBy upn, count(events) >= 5 sur 10 min`
- **Justification** : FP moyen->faible apres correction. 500121 = creds DEJA valides + spam de prompts. NE PAS inclure 50074/50076/authenticationRequirement (FP massif). Bonus: correler avec connexion_reussie meme compte. Champs m365_status_error_code/m365_workload inexistants.

## #4 · T1219 — Remote Access Software (AnyDesk/TeamViewer/ScreenConnect/RustDesk/ngrok)
- **Tactique** : Command and Control  ·  **Priorité** : haute
- **Source** : Sysmon EID1 + corroboration DNS DC (*.anydesk.com) + app-control FortiGate
- **Requête** : `event_source:sysmon AND event_id:1 AND (winlogbeat_winlog_event_data_OriginalFileName:(AnyDesk.exe OR "TeamViewer.exe" OR ScreenConnect* OR "RustDesk.exe" OR "ngrok.exe") OR winlogbeat_winlog_event_data_Image:(*anydesk* OR *teamviewer* OR *screenconnect* OR *splashtop* OR *atera* OR *rustdesk* OR *gotoassist* OR *remoteutilities* OR *zohoassist* OR *action1* OR *pulseway*)) AND NOT winlogbeat_winlog_event_data_Image:(*\\ProgramData\\OMNITECH-RMM\\*)`
- **Justification** : FP moyen. Vecteur #1 ransomware PME, invisible aux regles AV/LOLBin. Prefixe Sysmon corrige (winlogbeat_winlog_event_data_*). Allowlist a refondre par signataire (NinjaRemote deja legitime), pas un seul chemin. Volet DNS-DC pour hotes sans Sysmon.

## #5 · T1556.006 — Modify Authentication Process: Multi-Factor Authentication
- **Tactique** : Credential Access (TA0006)  ·  **Priorité** : haute
- **Source** : M365 / Entra audit
- **Requête** : `event_source:m365 AND m365_workload:AzureActiveDirectory AND event_action:("Disable Strong Authentication" OR "Update conditional access policy" OR "Admin registered security info")`
- **Justification** : FP moyen. Persistance identitaire #1. SCINDER: 'Disable Strong Authentication' = alerte directe; 'security info' tout-venant = bruit a correler au risque/geo ou comptes privilegies. Retirer 'Set Company Information' et corriger bug precedence AND/OR.

## #6 · T1572 — Protocol Tunneling (ngrok / cloudflared / localtunnel / serveo)
- **Tactique** : Command and Control  ·  **Priorité** : haute
- **Source** : Sysmon EID22 (dns_query) + EID1 process + DNS DC
- **Requête** : `(event_source:sysmon AND event_id:1 AND winlogbeat_winlog_event_data_OriginalFileName:("cloudflared.exe" OR "ngrok.exe")) OR (event_source:sysmon AND event_id:22 AND dns_query:(*.ngrok.io OR *.ngrok-free.app OR *.ngrok.app OR *.trycloudflare.com OR *.loca.lt OR *.serveo.net OR *.lhr.life OR bore.pub OR pinggy.io OR localhost.run))`
- **Justification** : FP moyen. T1572 absent (tunneling DNS existant = entropie). Champ corrige dns_query. NE PAS elargir trycloudflare->cloudflare (CDN). Volet process car un tunnel Cloudflare nomme ne resout aucun trycloudflare.com. Allowlister ingenieurs OMNITECH.

## #7 · T1203 — Exploitation for Client Execution (navigateur/PDF engendre un interpreteur)
- **Tactique** : Execution (TA0002)  ·  **Priorité** : haute
- **Source** : Sysmon EID1
- **Requête** : `event_source:sysmon AND event_id:1 AND winlogbeat_winlog_event_data_ParentImage:(*\\chrome.exe OR *\\msedge.exe OR *\\firefox.exe OR *\\AcroRd32.exe OR *\\Acrobat.exe OR *\\iexplore.exe) AND winlogbeat_winlog_event_data_Image:(*\\cmd.exe OR *\\powershell.exe OR *\\wscript.exe OR *\\cscript.exe OR *\\mshta.exe)`
- **Justification** : FP moyen. office_spawn_shell ne couvre que parents Office; ensemble parent navigateur/PDF disjoint. Enfants surs (ps/cmd/wscript/mshta) en alerte; conditionner rundll32/regsvr32/schtasks a cmdline suspecte. Baseline 7-30j.

## #8 · T1484.002 — Domain Policy Modification: Domain Trust Modification
- **Tactique** : Privilege Escalation (TA0004)  ·  **Priorité** : moyenne
- **Source** : Windows Security (DC) via Winlogbeat
- **Requête** : `winlogbeat_winlog_channel:"Security" AND winlogbeat_winlog_event_id:(4706 OR 4707 OR 4716 OR 4865 OR 4866 OR 4867)`
- **Justification** : FP faible. Sous-technique soeur de gpo_modification (T1484.001) deja en place, trou flague dans COUVERTURE-MITRE. Prereq: verifier sous-categorie 'Authentication Policy Change' active sur DC + ajouter a la regle 'Source silencieuse'. Enrichir SubjectUserName.

## #9 · T1114.002 — Email Collection / Transfer to Cloud (eDiscovery/export, fusion T1537)
- **Tactique** : Collection (TA0009)  ·  **Priorité** : moyenne
- **Source** : M365 Management Activity (Audit.Exchange / SecurityComplianceCenter)
- **Requête** : `event_source:m365 AND m365_workload:(Exchange OR SecurityComplianceCenter) AND event_action:("New-ComplianceSearch" OR "New-ComplianceSearchAction" OR "New-MailboxExportRequest")`
- **Justification** : FP faible. Fusionne T1114.002 et T1537 (meme requete/source). Champs corriges (event_action, pas m365_operation). RETIRER New-MailboxSearch/Search-Mailbox (cmdlets mortes EXO). Tierer severite sur -Export/-Purge. Allowlist comptes migration.

## #10 · T1555.004 — Credentials from Password Stores: Windows Credential Manager
- **Tactique** : Credential Access (TA0006)  ·  **Priorité** : moyenne
- **Source** : Sysmon EID1 (command_line)
- **Requête** : `event_source:sysmon AND event_id:1 AND ((command_line:cmdkey* AND command_line:*\/list*) OR (command_line:*vaultcmd* AND command_line:*\/list*) OR (process_name:rundll32.exe AND command_line:*keymgr.dll*))`
- **Justification** : FP faible. Sous-technique absente (voisins = T1003/T1555.005). Champs corriges (command_line, pas process_command_line). cmdkey/vaultcmd /list rares. Allowlist IT/provisioning RDP, baseline 10-14j.

## #11 · T1078.004 — Valid Accounts: Cloud Accounts (legacy auth = bypass MFA)
- **Tactique** : Initial Access (TA0001)  ·  **Priorité** : haute
- **Source** : M365 / Entra sign-in (champ client_app)
- **Requête** : `event_source:m365 AND m365_type:signin AND event_action:connexion_reussie AND client_app:("IMAP4" OR "POP3" OR "Authenticated SMTP" OR "Other clients")`
- **Justification** : FP eleve a maitriser. Aucune detection sur client_app; legacy auth FR (BEC) ne declenche aucune regle geo. RETIRER MAPI Over HTTP/ActiveSync/AutoDiscover (modernes). Allowlist baseline 1461 'Authenticated SMTP' (MFP) via 81, idealement first-seen par compte. Palliatif jusqu'au blocage Conditional Access.

## #12 · T1098.005 — Account Manipulation: Device Registration / ajout methode MFA
- **Tactique** : Persistence (TA0003)  ·  **Priorité** : haute
- **Source** : M365 / Entra directoryAudits
- **Requête** : `event_source:m365 AND m365_type:audit AND event_action:("Add registered owner to device" OR "Add registered users to device")`
- **Justification** : FP eleve a maitriser. Scenario AiTM survivant au reset MDP. SCINDER: device registration = alerte (rare); 'User registered security info' = bruit a correler au risque/geo. Valider les activityDisplayName REELS via GET directoryAudits 30j.

## #13 · T1204.002 — User Execution: Malicious File (archiveur/Outlook -> binaire frais)
- **Tactique** : Execution (TA0002)  ·  **Priorité** : haute
- **Source** : Sysmon EID1
- **Requête** : `event_source:sysmon AND event_id:1 AND winlogbeat_winlog_event_data_ParentImage:(*\\WinRAR.exe OR *\\7zFM.exe OR *\\7zG.exe OR *\\outlook.exe) AND winlogbeat_winlog_event_data_Image:(*\\Downloads\\* OR *\\Temp\\* OR *\\AppData\\Local\\*) AND winlogbeat_winlog_event_data_Image:(*.scr OR *.pif OR *.com OR *.js OR *.vbs OR *.hta OR *.lnk)`
- **Justification** : FP eleve a maitriser. Chaine loader (QakBot/IcedID) non couverte. RETIRER Explorer.EXE+*.exe+AppData (flood). Durcir extensions a faible legitimite. AJOUTER volet ISO reel (Image depuis lettre != C:) sinon cas phare rate. Tag+seuil/dedup par host.

## #14 · T1546.003 — Event Triggered Execution: WMI Event Subscription
- **Tactique** : Persistence (TA0003)  ·  **Priorité** : moyenne
- **Source** : Sysmon EID 19/20/21 (WmiEvent)
- **Requête** : `event_source:sysmon AND event_id:(19 OR 20 OR 21) AND winlogbeat_winlog_channel:"Microsoft-Windows-Sysmon/Operational" AND NOT winlogbeat_winlog_event_data_Consumer:(*"SCM Event Log"* OR *BVTConsumer*)`
- **Justification** : FP faible apres bornage. Persistance fileless non couverte. BORNAGE CHANNEL OBLIGATOIRE: sans lui EID21 entre en collision avec RDP TerminalServices = flood. Volume EID19/20/21 tres bas. Enrichir consumers ESET legitimes. Baseline 1-2 sem.

## #15 · T1505.005 — Server Software Component: ESXi (VIB rogue / script de demarrage)
- **Tactique** : Persistence (TA0003)  ·  **Priorité** : moyenne
- **Source** : vSphere/ESXi shell.log (input 1516, stream OMNI - vSphere)
- **Requête** : `event_source:vsphere AND message:("esxcli software acceptance set" OR "--no-sig-check" OR "CommunitySupported" OR "/etc/rc.local" OR ("vib install" AND "--force"))`
- **Justification** : FP moyen. Persistance hote ESXi non couverte; AJOUTER 'esxcli software acceptance set' (discriminant n1, manquant). SCINDER haute-fid (no-sig-check/CommunitySupported/--force) vs informatif (vib install/advanced set/rc.local, supprime en maintenance). Ne capte que l'interactif shell.log.

## #16 · T1562.008 — Impair Defenses: Disable or Modify Cloud Logs
- **Tactique** : Defense Evasion (TA0005)  ·  **Priorité** : moyenne
- **Source** : M365 Management Activity (Audit.Exchange)
- **Requête** : `event_source:m365 AND m365_workload:Exchange AND event_action:("Set-AdminAuditLogConfig" OR "Set-MailboxAuditBypassAssociation" OR "Disable-MailboxAuditLog" OR "Remove-MailboxAuditBypassAssociation")`
- **Justification** : FP moyen. Parite cloud manquante avec le 1102 on-prem. Champs corriges (event_action). SUPPRIMER la clause m365_parameters (non indexee -> 0 hit) et Set-Mailbox/Set-OrganizationConfig (bruit). Allowlist principals Microsoft.

## #17 · T1562.004 — Impair Defenses: Disable or Modify System Firewall
- **Tactique** : Defense Evasion (TA0005)  ·  **Priorité** : moyenne
- **Source** : Sysmon EID1
- **Requête** : `event_source:sysmon AND event_id:1 AND winlogbeat_winlog_event_data_Image:(*\\netsh.exe OR *\\powershell.exe) AND ((command_line:*advfirewall* AND command_line:*state* AND command_line:*off*) OR (command_line:*Set-NetFirewallProfile* AND command_line:*Enabled* AND command_line:*False*) OR (command_line:*opmode* AND command_line:*disable*))`
- **Justification** : FP moyen. Pare-feu hote non couvert (existant = Defender/services). Implementer en pipeline contains() ET-ennes (wildcards Lucene inutilisables dans une phrase). SUPPRIMER la branche 'add allowedprogram' (legacy installeurs = flood). Allowlist installeurs/MSI.

## #18 · T1531 — Account Access Removal (suppression/desactivation de masse)
- **Tactique** : Impact (TA0040)  ·  **Priorité** : moyenne
- **Source** : Windows Security (4724/4725/4726) + M365 audit (Delete user/Disable account)
- **Requête** : `winlogbeat_winlog_channel:"Security" AND winlogbeat_winlog_event_id:(4725 OR 4726) AND NOT winlogbeat_winlog_event_data_SubjectUserName:(*$ OR MSOL_* OR svc_*) | card(winlogbeat_winlog_event_data_TargetUserName) >= 5 sur 10 min`
- **Justification** : FP moyen. Seuls 4720/4740 cables; eviction de comptes non couverte. Champs corriges (_winlog_, card(target) pas count). SEPARER 4724 (reset onboarding). Volet cloud via directoryAudits (event_action), PAS Management Activity. Tripwire fin de chaine.

## #19 · T1561.001 — Disk Wipe: Disk Content Wipe (cipher/sdelete/diskpart/format)
- **Tactique** : Impact (TA0040)  ·  **Priorité** : moyenne
- **Source** : Sysmon EID1
- **Requête** : `event_source:sysmon AND event_id:1 AND (winlogbeat_winlog_event_data_OriginalFileName:("cipher.exe" OR "sdelete.exe") OR (command_line:*cipher* AND command_line:*\/w*) OR (command_line:*diskpart* AND command_line:*clean*) OR (command_line:*format* AND command_line:*\/y*))`
- **Justification** : FP moyen. Anti-forensique distinct de T1490 deja couvert. RETIRER fsutil deletejournal (doublon). Volet Linux dd/shred NON faisable (pas d'auditd execve). Allowlist provisioning/IT, tier-2. Ne captera pas les wipers raw-disk.

## #20 · T1529 — System Shutdown/Reboot (boot mode sans echec pre-chiffrement)
- **Tactique** : Impact (TA0040)  ·  **Priorité** : moyenne
- **Source** : Sysmon EID1 (+ System 1074 en correlation)
- **Requête** : `event_source:sysmon AND event_id:1 AND command_line:*bcdedit* AND command_line:*safeboot*`
- **Justification** : FP quasi nul sur cette branche. bcdedit safeboot (LockBit/Akira) detecte nulle part, signal pre-ransomware -> count>=1. La branche 1074/shutdown /f est du bruit PME -> enrichissement/correlation, pas alerte unitaire. Prefixe corrige.

## #21 · T1082 — System/Owner/Network Discovery (rafale d'orientation)
- **Tactique** : Discovery  ·  **Priorité** : moyenne
- **Source** : Sysmon EID1 (agregation oms-xdr/Graylog)
- **Requête** : `event_source:sysmon AND event_id:1 AND winlogbeat_winlog_event_data_Image:(*\\systeminfo.exe OR *\\whoami.exe OR *\\hostname.exe OR *\\ipconfig.exe OR *\\route.exe OR *\\arp.exe OR *\\tasklist.exe OR *\\quser.exe) | groupBy(winlogbeat_host_name) count(distinct Image) >= 4 sur 5 min`
- **Justification** : FP moyen. Burst hands-on-keyboard non correle. RETIRER nltest (doublon recon AD). Verifier que la conf Sysmon ne filtre pas ces binaires. Deployer en contributeur de score UEBA + allowlist comptes service/sous-reseaux IT, pas alerte standalone.

## #22 · T1087.004 — Cloud Account Discovery (AADInternals / Get-MgUser)
- **Tactique** : Discovery  ·  **Priorité** : moyenne
- **Source** : Sysmon EID1 (volet M365 retire)
- **Requête** : `event_source:sysmon AND event_id:1 AND command_line:(*AADInternals* OR *Invoke-AADIntRecon* OR *Get-MgUser* OR *Get-AzureADUser* OR *Get-MsolUser*)`
- **Justification** : FP moyen. Recon annuaire CLOUD non couverte (existant = on-prem). Champ corrige. SCINDER: AADInternals = haute (zero FP); cmdlets Get-Mg/AzureAD/Msol = basse + allowlist postes admin. Volet M365 SUPPRIME (lectures d'annuaire non loggees).

## #23 · T1518.001 — Security Software Discovery
- **Tactique** : Discovery  ·  **Priorité** : moyenne
- **Source** : Sysmon EID1 + ScriptBlock 4104 (Get-Mp*) en complement
- **Requête** : `event_source:sysmon AND event_id:1 AND (command_line:*"sc query windefend"* OR (command_line:*wmic* AND command_line:*SecurityCenter2*) OR command_line:*AntiVirusProduct*)`
- **Justification** : FP eleve a maitriser. Decouverte AV/EDR non couverte. RETIRER imperativement *MsMpEng*/*ESET*/*ekrn*/*egui* (processus des produits = flood). 2 regles: EID1 (process) + 4104 (cmdlets Get-Mp*). Score UEBA + correlation tamper, pas tier-1.

## #24 · T1571 — Non-Standard Port (sortie LAN vers port C2 atypique)
- **Tactique** : Command and Control  ·  **Priorité** : moyenne
- **Source** : FortiGate trafic forward multi-site
- **Requête** : `subtype:forward AND action:accept AND srcintfrole:lan AND dest_port:(4444 OR 1337 OR 31337 OR 50050 OR 6666) AND NOT dest_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16 OR 100.64.0.0/10)`
- **Justification** : FP moyen. Angle sortant atypique non couvert. Corriger srcintfrole (pas srcintf_role) + CIDR RFC1918 complet (172.16/12). SCINDER: ports C2-defaut = alerte; 8081/9001/7777/5555 = hunt (aimants a FP). app-ctrl pas garanti sur chaque site.

## #25 · T1496 — Resource Hijacking (cryptomining)
- **Tactique** : Impact (TA0040)  ·  **Priorité** : moyenne
- **Source** : Sysmon EID22 (dns_query) + FortiGate egress (dest_port)
- **Requête** : `(event_source:sysmon AND event_id:22 AND dns_query:(*minexmr* OR *nanopool* OR *supportxmr* OR *moneroocean* OR *ethermine* OR *2miners*)) OR (subtype:forward AND dest_port:(3333 OR 4444 OR 5555 OR 14444))`
- **Justification** : FP moyen. T1496 absent partout. Volet DNS-DC inexistant (canal Audit) -> dns_query Sysmon + dest_port Forti (couvre Linux/vSphere/conteneurs). 'service' Forti != port (utiliser dest_port). Preferer lookup CSV de pools cure aux wildcards *xmr*.

## #26 · T1568.002 — Dynamic Resolution: Domain Generation Algorithms
- **Tactique** : Command and Control  ·  **Priorité** : moyenne
- **Source** : Sysmon EID22 (QueryStatus=9003 NXDOMAIN) - extension omni-ndr-dns
- **Requête** : `event_source:sysmon AND event_id:22 AND winlogbeat_winlog_event_data_QueryStatus:9003 | count(distinct domaine enregistre) > 30 GROUP BY host sur 10 min (entropie label > 3.5)`
- **Justification** : FP moyen. DGA passe a travers omni-ndr-dns (topologie inverse). La source DC NXDOMAIN proposee N'EXISTE PAS -> Sysmon EID22 QueryStatus=9003 (attribution host native). Allowlist anti-sondes-Chrome obligatoire. Discriminer sur cardinalite de domaines DISTINCTS.

## #27 · T1213.002 — Data from Information Repositories: SharePoint/OneDrive
- **Tactique** : Collection (TA0009)  ·  **Priorité** : moyenne
- **Source** : M365 Management Activity (Audit.SharePoint)
- **Requête** : `event_source:m365 AND m365_workload:(SharePoint OR OneDrive) AND event_action:FileDownloaded | groupBy upn, count > seuil sur 15 min (exclure comptes/app de sync)`
- **Justification** : FP eleve a maitriser. Collecte/exfil par download cloud non couverte. Champs corriges (event_action/upn). RETIRER FileSyncDownloadedFull (re-sync OneDrive = milliers d'events) et SearchQueryPerformed du seuil. Allowlist app principals backup/migration.

## #28 · T1560.001 — Archive Collected Data: Archive via Utility (staging)
- **Tactique** : Collection (TA0009)  ·  **Priorité** : moyenne
- **Source** : Sysmon EID1
- **Requête** : `event_source:sysmon AND event_id:1 AND ((winlogbeat_winlog_event_data_OriginalFileName:(Rar.exe OR 7z.exe OR 7za.exe) AND (command_line:*\-hp* OR command_line:*\-p* OR command_line:*\-mx9*)) OR command_line:*Compress-Archive*) AND NOT winlogbeat_winlog_event_data_ParentImage:(*\\veeam* OR *\\backup*)`
- **Justification** : FP eleve a maitriser. Etape staging non couverte. SUPPRIMER la branche OriginalFileName seule (chaque lancement 7-Zip = flood); garder flags haute-fid -hp/-p/-mx9. Correler avec acces massif fichiers prealable. Valider tokenisation phrase+wildcard.

## #29 · T1021.001 — Remote Services: RDP (pivot single-hop / poste-a-poste)
- **Tactique** : Lateral Movement (TA0008)  ·  **Priorité** : moyenne
- **Source** : Windows Security 4624 type 10 + enrichissement net_segment
- **Requête** : `event_id:4624 AND logon_type_label:rdp_interactif_distant AND NOT winlogbeat_winlog_event_data_TargetUserName:(adm-* OR *$) | filtre net_segment: source user-vlan -> serveurs, OU poste->poste`
- **Justification** : FP eleve a maitriser. La regle fan-out (>=15 hotes) laisse passer le pivot 1->1. Utiliser logon_type_label:rdp_interactif_distant (pas LogonType:10) et prefixe _winlog_. SCOPER peer-workstation OU non-admin->serveur + allowlist adm-* (sinon flood RDP admin quotidien).

## #30 · T1570 — Lateral Tool Transfer (depot binaire sur C$/ADMIN$)
- **Tactique** : Lateral Movement (TA0008)  ·  **Priorité** : moyenne
- **Source** : Windows Security 5145 (ou Sysmon EID11 en repli)
- **Requête** : `winlogbeat_winlog_channel:"Security" AND winlogbeat_winlog_event_id:5145 AND winlogbeat_winlog_event_data_ShareName:(*C$ OR *ADMIN$) AND winlogbeat_winlog_event_data_RelativeTargetName:(*.exe OR *.dll OR *.ps1 OR *.bat OR *.scr) AND NOT winlogbeat_winlog_event_data_SubjectUserName:*$`
- **Justification** : FP eleve a maitriser. Depot d'outil sur partage admin non couvert. BLOQUANT: audit Detailed File Share en Failure-only -> copie reussie non journalisee; flipper en Success sur serveurs critiques OU Sysmon EID11. Prefixe corrige. Allowlist NinjaOne/GPO-deploy AVANT activation.

## #31 · T1550.002 — Use Alternate Authentication Material: Pass the Hash
- **Tactique** : Lateral Movement (TA0008)  ·  **Priorité** : moyenne
- **Source** : Windows Security 4624 type 3
- **Requête** : `event_id:4624 AND winlogbeat_winlog_event_data_LogonType:3 AND winlogbeat_winlog_event_data_AuthenticationPackageName:NTLM AND winlogbeat_winlog_event_data_LogonProcessName:NtLmSsp* AND NOT winlogbeat_winlog_event_data_TargetUserName:(*$ OR ANONYMOUS*) AND winlogbeat_winlog_event_data_TargetUserName:*adm*`
- **Justification** : FP eleve a maitriser. Pattern PtH non cible. Prefixe corrige (_winlog_, sinon 0 hit). RETIRER *svc* (NTLM continu = flood). Mieux: LogonType 9 (NewCredentials)+NtLmSsp, ou correler oms-xdr (LSASS/NTDS puis NTLM type3). A implementer en correlation.

## #32 · T1550.003 — Use Alternate Authentication Material: Pass the Ticket / Overpass-the-Hash
- **Tactique** : Lateral Movement (TA0008)  ·  **Priorité** : moyenne
- **Source** : Windows Security 4768 (DC)
- **Requête** : `winlogbeat_winlog_channel:"Security" AND winlogbeat_winlog_event_id:4768 AND winlogbeat_winlog_event_data_TicketEncryptionType:0x17 AND NOT winlogbeat_winlog_event_data_TargetUserName:(*$ OR krbtgt)`
- **Justification** : FP eleve a maitriser. Downgrade RC4 sur TGT non couvert. RC4 utilisateur reste courant (apps/trust/legacy). Durcissements: allowlist comptes RC4 (audit UAC/SPN reel), preferer la DEVIATION par compte (AES habituel -> RC4), correler hote source. Refuser la requete brute.

## #33 · T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket (usage)
- **Tactique** : Credential Access (TA0006)  ·  **Priorité** : moyenne
- **Source** : Windows Security 4768/4769 (DC) via oms-xdr
- **Requête** : `winlogbeat_winlog_channel:"Security" AND winlogbeat_winlog_event_id:4769 AND (compte demandeur inexistant/desactive OU anomalie duree de vie TGT) -- correlation stateful oms-xdr (4769 sans 4768 prealable, dedup par compte)`
- **Justification** : FP eleve a maitriser. Usage de ticket forge non couvert, MAIS requete RC4-only = doublon Kerberoasting. Pivoter vers artefacts discriminants (compte inexistant/desactive, TGT 10 ans, incoherence RID). RETIRER Silver (non observable cote DC). Anti-join -> oms-xdr stateful.

## #34 · T1199 — Trusted Relationship (creation/redemption d'invite externe M365)
- **Tactique** : Initial Access (TA0001)  ·  **Priorité** : moyenne
- **Source** : M365 / Entra directoryAudits
- **Requête** : `event_source:m365 AND m365_type:audit AND event_action:("Invite external user" OR "Redeem external user invitation")`
- **Justification** : FP eleve sur la requete login proposee. Surface B2B non instrumentee, mais la requete login-guest = inventaire (flood). BASCULER sur la CREATION/redemption de guest (rare, haut signal). Tag is_guest puis alerte ciblee (1ere connexion / guest dormant / app sensible).

## #35 · T1589.002 — Gather Victim Identity Information: Email Addresses (enumeration M365)
- **Tactique** : Reconnaissance (TA0043)  ·  **Priorité** : moyenne
- **Source** : M365 / Entra sign-in (status_code 50034)
- **Requête** : `event_source:m365 AND m365_type:signin AND status_code:50034 | groupBy src_ip, count(distinct user) >= 10 sur 1h (exclure IP egress corp)`
- **Justification** : FP eleve a maitriser. Fan-out '50034 distinct par IP' absent. Champs corriges (m365_type:signin/status_code). NE PAS la presenter comme couverture de l'enumeration silencieuse (GetCredentialType ne logue rien). Early-warning P3, exclure IP egress corp.

## #36 · T1595.003 — Active Scanning: Wordlist Scanning (chemins sensibles WAF)
- **Tactique** : Reconnaissance (TA0043)  ·  **Priorité** : moyenne
- **Source** : BunkerWeb WAF
- **Requête** : `alert_tag:bunkerweb AND (url:"/.git*" OR url:"/.env" OR url:"/.aws*" OR url:"/actuator*" OR url:"/server-status*") AND http_status:(200 OR 301 OR 302 OR 500)`
- **Justification** : FP eleve a maitriser. Hit unique en 200 sur /.git ou /.env (leak secrets) rate par 'WAF scan 404'/'pic blocages'. CIBLER 200/301/302/500 et EXCLURE 403/404 ('NOT 404' inclut les 403 bloques = flood). RETIRER security.txt (RFC 9116)/phpinfo/wp-login. Seuil >=N chemins distincts/IP.

## #37 · T1566.002 — Phishing: Spearphishing Link (visite domaine phishing autorisee)
- **Tactique** : Initial Access (TA0001)  ·  **Priorité** : moyenne
- **Source** : FortiGate web-filter UTM (subtype:webfilter)
- **Requête** : `subtype:webfilter AND NOT action:blocked AND cat:(61 OR 88) | group by src_ip, fortigate_site`
- **Justification** : FP eleve a maitriser. subtype:webfilter inexploite (couche HTTP/SNI distincte du DNS/IP). Utiliser ID FortiGuard numeriques (Phishing 61, NOD 88) pas catdesc (fragile). SORTIR 'NOD'/'Spam URLs' du seuil critique. group by src_ip (user souvent null). Couverture probablement BDX-only.

## #38 · T1025 — Removable Media: insertion/acces/exfil USB (fusion T1091/T1052.001)
- **Tactique** : Collection / Exfiltration  ·  **Priorité** : moyenne
- **Source** : Windows Security 6416/4663 (ou Sysmon EID9/11 alternative)
- **Requête** : `winlogbeat_winlog_channel:"Security" AND winlogbeat_winlog_event_id:6416 AND winlogbeat_winlog_event_data_ClassName:DiskDrive -- correler 4663 (acces fichier media amovible) avec seuil de volume`
- **Justification** : FP eleve, prereq GPO. Fusionne T1091/T1025/T1052.001. PREREQ NON REMPLI: 6416 exige 'Audit PNP Activity' et 4663 exige 'Audit Removable Storage', OFF par defaut -> GPO + valider par injection. RETIRER 6424 (faux). ClassName:DiskDrive (6416 brut = clavier/souris = flood). Scoper serveurs/DC ou seuil volume + allowlist serials. P2/backlog.

## #39 · T1102 — Web Service / Text Storage Sites (C2 + exfil via SaaS, fusion T1567.003)
- **Tactique** : Command and Control / Exfiltration  ·  **Priorité** : moyenne
- **Source** : Sysmon EID22 + FortiGate web-filter (URL+process) pour correlation
- **Requête** : `event_source:sysmon AND event_id:22 AND winlogbeat_winlog_event_data_QueryName:(*discord.com OR api.telegram.org OR *pastebin.com OR paste.ee OR transfer.sh OR gofile.io OR anonfiles.com) AND NOT winlogbeat_winlog_event_data_Image:(*\\chrome.exe OR *\\msedge.exe OR *\\firefox.exe OR *\\Discord.exe OR *\\slack.exe OR *\\Telegram.exe OR *\\git.exe OR *\\OneDrive.exe)`
- **Justification** : FP eleve a maitriser. Fusionne T1102/T1567.003. Le domaine-nu = 100% FP DEJA tranche (66-threatintel: 3460 ev/7j exclus). Seule valeur neuve = filtre par PROCESSUS. SCOPER serveurs/DC (resolution rare = signal fort), allowlist clients desktop, sortir raw.githubusercontent en hunt. Prefixe corrige.

## #40 · T1127.001 — Trusted Developer Utilities Proxy Execution: MSBuild
- **Tactique** : Execution (TA0002)  ·  **Priorité** : basse
- **Source** : Sysmon EID1
- **Requête** : `event_source:sysmon AND event_id:1 AND winlogbeat_winlog_event_data_Image:*\\MSBuild.exe AND winlogbeat_winlog_event_data_ParentImage:(*\\winword.exe OR *\\excel.exe OR *\\powershell.exe OR *\\wscript.exe OR *\\mshta.exe)`
- **Justification** : FP eleve, deja ecarte. ECARTE volontairement par l'equipe (85: 9183 hits = postes dev). Detecter sur ParentImage anormal (Office/script) ou inline-task en %TEMP%, PAS extension (*.csproj matche tous les builds). Corriger taxonomie (msdt=T1218, dnx obsolete).

## #41 · T1201 — Password Policy Discovery
- **Tactique** : Discovery  ·  **Priorité** : basse
- **Source** : Sysmon EID1 (volet Linux abandonne)
- **Requête** : `event_source:sysmon AND event_id:1 AND (command_line:*"net accounts"* OR command_line:*Get-ADDefaultDomainPasswordPolicy* OR command_line:*Get-ADFineGrainedPasswordPolicy*)`
- **Justification** : FP eleve. NE PAS creer une 131e alerte: AJOUTER ces motifs (tag pwpolicy_discovery, T1201) a omni-extra-10-discovery comme feeder de correlation pre-spray. Champs corriges. Volet Linux abandonne (pas d'auditd execve). Jamais standalone (PingCastle/audit ISO27001 internes).

## #42 · T1595.001 — Active Scanning: Scanning IP Blocks (scan WAN entrant)
- **Tactique** : Reconnaissance (TA0043)  ·  **Priorité** : basse
- **Source** : FortiGate trafic forward/deny multi-site
- **Requête** : `subtype:forward AND action:deny AND srcintfrole:wan | group by (src_ip, fortigate_site), count(distinct dest_port) >= 50 sur 5 min -- DASHBOARD uniquement`
- **Justification** : FP eleve, NE PAS deployer en alerte. Exclusion entrant WAN deja deliberee (48). action=deny = deja bloque, bruit de fond (Shodan/CGNAT/CDN) = flood. Corriger srcintfrole:wan (pas srcintf:wan1) + supprimer NOT _exists_:internal_src (champ fantome). Garder en DASHBOARD ou correlation oms-xdr 'scan deny PUIS flux accepte'.

