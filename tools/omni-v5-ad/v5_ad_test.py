#!/usr/bin/env python3
# Tests des règles v5 chantier 1 (messages synthétiques, rien n'est indexé ni notifié).
# Avant application : simulateur de règle (/system/pipelines/rule/simulate) ; après : --flux = simulateur de stream
# (/system/pipelines/simulate), qui rejoue TOUTE la chaîne du stream (enrichissements existants + étape 45).
# Les valeurs propres au site (compte leurre, compte Entra Connect, DC, PKI, canaris...) viennent de site.json
# via v5_ad_build ; les autres identités sont fictives.
import json, sys, uuid
sys.path.insert(0, "/root/omni-v5-ad")
sys.argv = [sys.argv[0], "--test"] + sys.argv[1:]
import v5_ad_build as b
FLUX = "--flux" in sys.argv
W = "winlogbeat_winlog_event_data_"
def w(eid, **kv): d = {"winlogbeat_winlog_event_id": str(eid), "event_source": "windows_security", "winlogbeat_winlog_channel": "Security"}; d.update({W + k: v for k, v in kv.items()}); return d
R_LEURRE = f"omni-v5-ad-leurre-{b.LEURRE}"
ENTRA = b.SITE["compte_entra_connect"]
DC1 = b.SITE["comptes_replication"][0]
CA = b.SITE["compte_machine_ca"]
T0_DC, T0_PKI = b.TIER0[0].upper(), b.TIER0[-1].upper()
CAS = [  # (règle, stream, champs, tag attendu)
 ("omni-v5-ad-kerberoast-aes", "OMNI - Windows Security", w(4769, Status="0x0", ServiceName="svc_sqlprod", TargetUserName="jdupont@OMNITECH.SECURITY", TicketEncryptionType="0x12"), "kerberoast_aes"),
 ("omni-v5-ad-kerberoast-aes", "OMNI - Windows Security", w(4769, Status="0x0", ServiceName="mmartin", TargetUserName="mmartin@OMNITECH.SECURITY"), None),
 ("omni-v5-ad-kerberoast-aes", "OMNI - Windows Security", w(4769, Status="0x0", ServiceName="SRV-FICHIERS$", TargetUserName="jdupont@OMNITECH.SECURITY"), None),
 ("omni-v5-ad-kerberoast-aes", "OMNI - Windows Security", w(4769, Status="0x6", ServiceName="svc_sqlprod", TargetUserName="jdupont@OMNITECH.SECURITY"), None),
 (R_LEURRE, "OMNI - Windows Security", w(4769, Status="0x0", ServiceName=b.LEURRE, TargetUserName="jdupont@OMNITECH.SECURITY"), b.TAG_LEURRE),
 (R_LEURRE, "OMNI - Windows Security", w(4771, TargetUserName=b.LEURRE), b.TAG_LEURRE),
 ("omni-v5-ad-kerberoast-aes", "OMNI - Windows Security", w(4769, Status="0x0", ServiceName=b.LEURRE, TargetUserName="jdupont@OMNITECH.SECURITY"), None),
 ("omni-v5-ad-asrep-preparation", "OMNI - Windows Security", w(4738, UserAccountControl="\n\t\t%%2096", TargetUserName="jdupont", SubjectUserName="adm-x"), "asrep_preparation"),
 ("omni-v5-ad-asrep-preparation", "OMNI - Windows Security", w(5136, AttributeLDAPDisplayName="userAccountControl", OperationType="%%14674", AttributeValue="4194816", SubjectUserName="adm-x", ObjectDN="CN=J,OU=X"), "asrep_preparation"),
 ("omni-v5-ad-asrep-preparation", "OMNI - Windows Security", w(5136, AttributeLDAPDisplayName="userAccountControl", OperationType="%%14674", AttributeValue="66048", SubjectUserName="adm-x"), None),
 ("omni-v5-ad-dcsync", "OMNI - Windows Security", w(4662, Properties="%%7688\n\t\t{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}\n\t{19195a5b-6da0-11d0-afd3-00c04fd930c9}", SubjectUserName="SRV-FICHIERS$"), "dcsync"),
 ("omni-v5-ad-dcsync", "OMNI - Windows Security", w(4662, Properties="%%7688\n\t\t{89e95b76-444d-4c62-991a-0facbeda640c}", SubjectUserName="MSOL_deadbeef0001"), "dcsync"),
 ("omni-v5-ad-dcsync", "OMNI - Windows Security", w(4662, Properties="%%7688\n\t\t{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}", SubjectUserName=ENTRA), None),
 ("omni-v5-ad-dcsync", "OMNI - Windows Security", w(4662, Properties="%%7688\n\t\t{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}", SubjectUserName=DC1), None),
 ("omni-v5-ad-shadow-credentials", "OMNI - Windows Security", w(5136, AttributeLDAPDisplayName="msDS-KeyCredentialLink", SubjectUserName=DC1, SubjectUserSid="S-1-5-18", ObjectDN="CN=Jean,OU=X"), "shadow_credentials"),
 ("omni-v5-ad-shadow-credentials", "OMNI - Windows Security", w(5136, AttributeLDAPDisplayName="msDS-KeyCredentialLink", SubjectUserName=ENTRA, ObjectDN="CN=Jean,OU=X"), None),
 ("omni-v5-ad-shadow-credentials", "OMNI - Windows Security", w(5136, AttributeLDAPDisplayName="msDS-KeyCredentialLink", SubjectUserName="POSTE-X-LT$", ObjectDN="CN=POSTE-X-LT,OU=Y"), None),
 ("omni-v5-ad-adcs-san", "OMNI - Windows Security", w(4886, SubjectAlternativeName="Autre nom :\n     Nom principal=administrateur@omnitech.security", Requester="SECURITY\\jdupont", RequestId="99"), "adcs_san"),
 ("omni-v5-ad-adcs-san", "OMNI - Windows Security", w(4887, SubjectAlternativeName="Autre nom :\n     Nom principal=administrateur@omnitech.security", Requester="SECURITY\\jdupont", RequestId="99"), "adcs_san"),
 ("omni-v5-ad-adcs-san", "OMNI - Windows Security", w(4887, SubjectAlternativeName="Autre nom :\n     Nom principal=mmartin@exemple.fr\nNom RFC822=mmartin@exemple.fr", Requester="SECURITY\\mmartin", RequestId="98"), None),
 ("omni-v5-ad-adcs-san", "OMNI - Windows Security", w(4886, SubjectAlternativeName="Nom DNS=srv-web.omnitech.security", Requester="SECURITY\\adm-x", Attributes="CertificateTemplate:OMS-WebServer\nccm:DC01"), None),
 ("omni-v5-ad-adcs-san", "OMNI - Windows Security", w(4886, Attributes="CertificateTemplate:User\nSAN:upn=administrateur@omnitech.security", Requester="SECURITY\\jdupont"), "adcs_san"),
 ("omni-v5-ad-adcs-modele-ca", "OMNI - Windows Security", w(5136, ObjectClass="pKICertificateTemplate", ObjectDN="CN=OMS-WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=omnitech,DC=security", SubjectUserName="jdupont"), "adcs_modele_ca"),
 ("omni-v5-ad-adcs-modele-ca", "OMNI - Windows Security", w(4900, SubjectUserName="jdupont"), "adcs_modele_ca"),
 ("omni-v5-ad-adcs-modele-ca", "OMNI - Windows Security", w(5136, ObjectClass="certificationAuthority", AttributeLDAPDisplayName="cACertificateDN", SubjectUserName=CA, ObjectDN="CN=Root CA OMNITECH SECURITY,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=omnitech,DC=security"), None),
 ("omni-v5-ad-adcs-modele-ca", "OMNI - Windows Security", w(5136, ObjectClass="certificationAuthority", AttributeLDAPDisplayName="cACertificate", SubjectUserName="jdupont", ObjectDN="CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=omnitech,DC=security"), "adcs_modele_ca"),
 ("omni-v5-ad-service-tier0", "OMNI - Windows autres", {"winlogbeat_winlog_event_id": "7045", "source": T0_DC, W + "ServiceName": "PSEXESVC", W + "ImagePath": "%SystemRoot%\\PSEXESVC.exe"}, "service_tier0"),
 ("omni-v5-ad-service-tier0", "OMNI - Windows autres", {"winlogbeat_winlog_event_id": "7045", "source": T0_DC, W + "ServiceName": "VeeamVssSupport", W + "ImagePath": "C:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe", "winlogbeat_winlog_user_name": b.GMSA_SAUV + "T0$"}, None),
 ("omni-v5-ad-service-tier0", "OMNI - Windows autres", {"winlogbeat_winlog_event_id": "7045", "source": T0_DC, W + "ServiceName": "VeeamVssSupport", W + "ImagePath": "C:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe", "winlogbeat_winlog_user_name": "jdupont"}, "service_tier0"),
 ("omni-v5-ad-service-tier0", "OMNI - Windows autres", {"winlogbeat_winlog_event_id": "7045", "source": T0_PKI, W + "ServiceName": "eamonm", W + "ImagePath": "system32\\DRIVERS\\eamonm.sys"}, None),
 ("omni-v5-ad-service-tier0", "OMNI - Windows autres", {"winlogbeat_winlog_event_id": "7045", "source": T0_DC, W + "ServiceName": "NinjaOne NMS Delegate", W + "ImagePath": f"\"C:\\Program Files (x86)\\{b.RMM_DOSSIER}-5.8.9154\\nmsmanager.exe\" -j"}, None),
 ("omni-v5-ad-service-tier0", "OMNI - Windows autres", {"winlogbeat_winlog_event_id": "7045", "source": T0_PKI, W + "ServiceName": "vm3dmp", W + "ImagePath": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\vm3d.inf_amd64_eba3f0b96d8538e4\\vm3dmp.sys"}, None),
 ("omni-v5-ad-service-tier0", "OMNI - Windows autres", {"winlogbeat_winlog_event_id": "7045", "source": "POSTE-X-LT", W + "ServiceName": "PSEXESVC", W + "ImagePath": "%SystemRoot%\\PSEXESVC.exe"}, None),
 ("omni-v5-ad-gpo-sensible", "OMNI - Windows Security", w(5136, AttributeLDAPDisplayName="gPLink", ObjectClass="organizationalUnit", ObjectDN="OU=Domain Controllers,DC=omnitech,DC=security", SubjectUserName="adm-x"), "gpo_sensible"),
 ("omni-v5-ad-gpo-sensible", "OMNI - Windows Security", w(5136, AttributeLDAPDisplayName="versionNumber", ObjectClass="groupPolicyContainer", ObjectDN=f"CN={b.GPO_AGENT.upper()},CN=Policies,CN=System,DC=omnitech,DC=security", SubjectUserName=DC1, SubjectUserSid="S-1-5-18"), None),
 ("omni-v5-ad-gpo-sensible", "OMNI - Windows Security", w(5136, AttributeLDAPDisplayName="versionNumber", ObjectClass="groupPolicyContainer", ObjectDN="CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=omnitech,DC=security", SubjectUserName=DC1, SubjectUserSid="S-1-5-18"), "gpo_sensible"),
 ("omni-v5-ad-gpo-sensible", "OMNI - Windows Security", w(5136, AttributeLDAPDisplayName="gPLink", ObjectClass="organizationalUnit", ObjectDN="OU=Serveurs,OU=Site,DC=omnitech,DC=security", SubjectUserName="adm-x"), None),
 ("omni-v5-ad-lsass-lecture", "OMNI - Sysmon", {"winlogbeat_winlog_event_id": "10", "event_source": "sysmon", "source": "POSTE-X-LT", W + "TargetImage": "C:\\Windows\\system32\\lsass.exe", W + "SourceImage": "C:\\Windows\\System32\\WerFaultSecure.exe", W + "GrantedAccess": "0x1fffff"}, "lsass_lecture"),
 ("omni-v5-ad-lsass-lecture", "OMNI - Sysmon", {"winlogbeat_winlog_event_id": "10", "event_source": "sysmon", "source": "POSTE-X-LT", W + "TargetImage": "C:\\Windows\\system32\\lsass.exe", W + "SourceImage": "C:\\Users\\x\\AppData\\Local\\Temp\\a.exe", W + "GrantedAccess": "0x1418"}, "lsass_lecture"),
 ("omni-v5-ad-lsass-lecture", "OMNI - Sysmon", {"winlogbeat_winlog_event_id": "10", "event_source": "sysmon", "source": "POSTE-X-LT", W + "TargetImage": "C:\\Windows\\system32\\lsass.exe", W + "SourceImage": "C:\\Program Files (x86)\\NinjaOne\\NinjaRMMAgent.exe", W + "GrantedAccess": "0x1410"}, None),
 ("omni-v5-ad-lsass-lecture", "OMNI - Sysmon", {"winlogbeat_winlog_event_id": "10", "event_source": "sysmon", "source": "POSTE-X-LT", W + "TargetImage": "C:\\Windows\\system32\\lsass.exe", W + "SourceImage": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26100.4-0\\MsMpEng.exe", W + "GrantedAccess": "0x1410"}, None),
 ("omni-v5-ad-lsass-lecture", "OMNI - Sysmon", {"winlogbeat_winlog_event_id": "10", "event_source": "sysmon", "source": "POSTE-X-LT", W + "TargetImage": "C:\\Windows\\system32\\lsass.exe", W + "SourceImage": "C:\\Program Files\\Docker\\x.exe", W + "GrantedAccess": "0x100000"}, None),
 ("omni-v5-ad-canari-fichier", "OMNI - Windows Security", w(4663, ObjectName="D:\\Partages\\Compta\\" + b.CANARIS[0], SubjectUserName="jdupont", SubjectUserSid="S-1-5-21-1"), "canari_fichier"),
 ("omni-v5-ad-canari-fichier", "OMNI - Windows Security", w(4663, ObjectName="D:\\Partages\\Compta\\" + b.CANARIS[0], SubjectUserName="SRV-FICHIERS$", SubjectUserSid="S-1-5-18"), None),
 ("omni-v5-m365-transfert-externe", "OMNI - M365", {"event_source": "m365", "event_action": "Set-Mailbox", "user": "jdupont", "object": "Boite partagee X", "forward_external": 1, "fwd_target": "smtp:x@exemple-externe.com"}, "m365_transfert_externe"),
 ("omni-v5-m365-transfert-externe", "OMNI - M365", {"event_source": "m365", "event_action": "Set-Mailbox", "user": "mmartin", "object": "Boite partagee Y"}, None),
 ("omni-v5-m365-regle-boite-suspecte", "OMNI - M365", {"event_source": "m365", "event_action": "New-InboxRule", "user": "jdupont", "object": "EURP000/x/jdupont\\..", "src_ip_country_code": "FR"}, "m365_regle_boite_suspecte"),
 ("omni-v5-m365-regle-boite-suspecte", "OMNI - M365", {"event_source": "m365", "event_action": "UpdateInboxRules", "user": "jdupont", "src_ip_country_code": "NG"}, "m365_regle_boite_suspecte"),
 ("omni-v5-m365-regle-boite-suspecte", "OMNI - M365", {"event_source": "m365", "event_action": "New-InboxRule", "user": "mmartin", "object": "EURP000/x/abcd\\Classement-recapitulatifs", "src_ip_country_code": "FR"}, None),
 ("omni-v5-m365-regle-boite-suspecte", "OMNI - M365", {"event_source": "m365", "event_action": "set-InboxRule", "user": "mmartin", "object": "abcd1234-0000\\0000000000000000001", "src_ip_country_code": "FR"}, None),
 ("omni-v5-m365-mfa-defi", "OMNI - M365", {"event_source": "m365", "m365_type": "signin", "m365_fail_code": "50074", "user": "jdupont", "src_country": "NL", "app": "Office"}, "m365_mfa_defi"),
 ("omni-v5-m365-mfa-defi", "OMNI - M365", {"event_source": "m365", "m365_type": "signin", "m365_fail_code": "50126", "user": "jdupont", "src_country": "NL"}, None),
]
sid = b.streams_ids()
ok = ko = 0; premier = True
for regle, stream, champs, attendu in CAS:
    msg = {"_id": str(uuid.uuid4()), "message": "test v5 chantier 1 bx-qa-seal-vm", "source": champs.get("source", "test-v5-ad"), "timestamp": "2026-11-27T08:00:00.000Z"}; msg.update(champs)
    if FLUX:
        r = b.api("POST", "/system/pipelines/simulate", {"stream_id": sid[stream], "message": msg, "input_id": None})
        obtenu = None; etr = None
        for m in r.get("messages", []):
            mm = m.get("message") or {}; obtenu = mm.get("v5_tag", obtenu); etr = mm.get("v5_mfa_etranger", etr)
    else:
        r = b.api("POST", "/system/pipelines/rule/simulate", {"message": json.dumps(msg), "rule_source": {"title": regle, "description": "", "source": b.R[regle], "rule_builder": None}})
        if premier: print("cles reponse simulateur :", list(r.keys())[:10]); premier = False
        f = r.get("fields") or (r.get("message") or {}).get("fields") or r.get("message") or r
        obtenu = f.get("v5_tag") if isinstance(f, dict) else None; etr = f.get("v5_mfa_etranger") if isinstance(f, dict) else None
    bon = (obtenu == attendu); ok += bon; ko += (not bon)
    extra = f" mfa_etranger={etr}" if regle == "omni-v5-m365-mfa-defi" and attendu else ""
    print(("OK " if bon else "KO ") + f"{regle:<38} v5_tag={obtenu!r} (attendu {attendu!r}){extra}")
print(f"RESULTAT : {ok} OK / {ko} KO")
