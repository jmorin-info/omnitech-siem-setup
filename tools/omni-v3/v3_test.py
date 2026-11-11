#!/usr/bin/env python3
# Test des règles OMNI v3 via le simulateur de pipeline Graylog (messages synthétiques, rien n'est indexé).
import json, sys, importlib.util
spec = importlib.util.spec_from_file_location("b", "/root/omni-v3/v3_build.py"); b = importlib.util.module_from_spec(spec)
sys.argv = ["x", "--test"]; spec.loader.exec_module(b)
sid = b.streams_ids()
CAS = [
 ("OMNI - Windows Security", {"event_id": "4662", "winlogbeat_winlog_event_data_Properties": "%%7684 {e362ed86-b728-0842-b27d-2dea7a9df218}", "winlogbeat_winlog_event_data_SubjectUserName": "jdupont"}, "v3_tag", "gmsa_lecture_utilisateur"),
 ("OMNI - Windows Security", {"event_id": "4662", "winlogbeat_winlog_event_data_Properties": "{e362ed86-b728-0842-b27d-2dea7a9df218}", "winlogbeat_winlog_event_data_SubjectUserName": "BX-VEEAM-IT-SV$"}, "v3_tag", None),
 ("OMNI - Windows Security", {"event_id": "4768", "winlogbeat_winlog_event_data_TicketEncryptionType": "0x17"}, "v3_tag", "kerberos_chiffrement_faible"),
 ("OMNI - Windows Security", {"event_id": "4769", "winlogbeat_winlog_event_data_TicketEncryptionType": "0x17"}, "v3_tag", None),
 ("OMNI - Windows Security", {"event_id": "4624", "account_class": "admin", "winlogbeat_winlog_event_data_LogonType": "10", "host": "BX-AD-01-IT-VM.omnitech.security"}, "v3_actif", "tier0 - Controleur de domaine (PDC)"),
 ("OMNI - ESET", {"eset_event_type": "Threat_Event", "eset_outcome": "non_remediee", "eset_hostname": "bx-it-jmo-lt.omnitech.security"}, "v3_tag", "eset_non_remediee"),
 ("OMNI - ESET", {"eset_event_type": "Threat_Event", "eset_outcome": "remediee", "eset_hostname": "BX-PKI2022.omnitech.security"}, "v3_actif", "tier0 - Autorite de certification"),
 ("OMNI - FortiGate", {"logdesc": "Admin login successful", "user": "admin", "ui": "GUI(10.13.10.2)"}, "v3_tag", "fg_admin_local"),
 ("OMNI - FortiGate", {"logdesc": "Admin login successful", "user": "jmorin", "ui": "GUI(203.0.113.7)"}, "v3_tag", "fg_admin_ip_publique"),
 ("OMNI - FortiGate", {"logdesc": "Admin login successful", "user": "jmorin", "ui": "GUI(10.33.10.9)"}, "v3_tag", None),
 ("OMNI - FortiGate", {"logdesc": "Admin login failed", "user": "x", "ui": "https(10.33.50.250)"}, "v3_tag", "fg_admin_echec"),
 ("OMNI - Windows autres", {"winlogbeat_winlog_channel": "Veeam Backup", "event_id": "40210", "message": "Restore session has been initiated by 'SECURITY\\jdupont'."}, "v3_tag", "veeam_restauration_inattendue"),
 ("OMNI - Windows autres", {"winlogbeat_winlog_channel": "Veeam Backup", "event_id": "40210", "message": "Restore session has been initiated by 'SECURITY\\adm-jmorin'."}, "v3_tag", None),
 ("OMNI - Windows autres", {"winlogbeat_winlog_channel": "Veeam Backup", "event_id": "23090", "message": "Backup job 'BX-SOCLE-QUOT' has been deleted."}, "v3_tag", "veeam_suppression"),
 ("OMNI - Windows autres", {"winlogbeat_winlog_channel": "Veeam Backup", "event_id": "30800", "message": "Virtual lab Virtual Lab OMS has been deleted."}, "v3_tag", None),
 ("OMNI - Windows autres", {"winlogbeat_winlog_channel": "Veeam Backup", "event_id": "190", "message": "Backup job 'BX-BCK-CRITIQUE-1H-LIGHT' finished with Success.\nAll objects have been backed up successfully."}, "veeam_result", "success"),
 ("OMNI - Windows autres", {"winlogbeat_winlog_channel": "Veeam Backup", "event_id": "490", "message": "Backup Copy job 'BX-CPY-CHEOPS-SECU-QUOT' finished with Warning."}, "veeam_job", "BX-CPY-CHEOPS-SECU-QUOT"),
 ("OMNI - Windows autres", {"winlogbeat_winlog_channel": "Veeam Backup", "event_id": "150", "message": "VM BX-ADV-NAV2018-VM task has finished with 'Failed' state."}, "veeam_result", "failed"),
 ("OMNI - Windows Security", {"event_id": "4887", "winlogbeat_winlog_event_data_CertificateTemplate": "UtilisateurAutoenrollement-OMS"}, "cert_template", "UtilisateurAutoenrollement-OMS"),
]
ok = ko = 0
for stream, champs, champ, attendu in CAS:
    import uuid
    msg = {"_id": str(uuid.uuid4()), "message": champs.get("message", "test omni-v3"), "source": "test-v3", "timestamp": "2026-11-11T10:00:00.000Z"}; msg.update(champs)
    r = b.api("POST", "/system/pipelines/simulate", {"stream_id": sid[stream], "message": msg, "input_id": None})
    obtenu = None
    for m in r.get("messages", []):
        obtenu = (m.get("message") or {}).get(champ, obtenu)
    bon = (obtenu == attendu)
    ok += bon; ko += (not bon)
    print(("OK " if bon else "KO ") + f"{stream[7:]:<16} {champ}={obtenu!r} (attendu {attendu!r})")
print(f"RESULTAT : {ok} OK / {ko} KO")
