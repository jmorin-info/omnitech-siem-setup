#!/usr/bin/env bash
# =============================================================================
# 59-file-audit.sh - Audit d'acces aux FICHIERS SENSIBLES (4663 / 5145).
#   Pour une boite de securite, l'acces aux donnees clients/IP = joyau. On
#   normalise et tague les acces fichier, en EXCLUANT le bruit systeme (CdRom,
#   C:\Windows, comptes machine). La PORTEE est definie cote serveur par les SACL
#   (4663) / l'audit "Detailed File Share" (5145) poses sur les seuls dossiers
#   sensibles -> tout 4663/5145 restant = acces a surveiller (alert_tag
#   file_sensitive_access, MITRE T1039 - comble la tactique Collection).
#   Detection d'exfiltration/ransomware (acces de masse) via alerte agregee (13).
#   Pipeline DEDIE connecte aux streams Windows. Idempotent. Relancer 13 + 14.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api
WD="winlogbeat_winlog_event_data"

echo "==> [1/4] MITRE (T1039 Data from Network Shared Drive / T1485 destruction)"
CSV="lookups/mitre-attack.csv"
add_mitre() { grep -q "^$1," "${CSV}" || { echo "$1,$2,$3,$4,$5,$6" >> "${CSV}"; ok "MITRE +$1"; }; }
add_mitre file_sensitive_access T1039 "Data from Network Shared Drive" "Collection" eleve 6
add_mitre file_delete_sensible  T1485 "Data Destruction"               "Impact"     eleve 7
install -m 644 "${CSV}" /etc/graylog/lookup/mitre-attack.csv
chown root:graylog /etc/graylog/lookup/mitre-attack.csv 2>/dev/null || true

echo "==> [2/4] Regles de parsing + detection"
# Normalisation : file_path (4663 ObjectName, ou 5145 ShareName+RelativeTargetName),
# accessor, type d'acces. Gate sur l'event_id brut -> pas de dependance inter-regles.
ensure_rule "omni-file-12-normalise" <<EOF
rule "omni-file-12-normalise"
when
  to_string(\$message.event_source) == "windows_security"
  AND ( to_long(\$message.event_id, 0) == 4663 OR to_long(\$message.event_id, 0) == 5145 )
then
  set_field("event_category", "acces_fichier");
  set_field("file_path", to_string(\$message.${WD}_ObjectName, to_string(\$message.${WD}_RelativeTargetName)));
  set_field("file_share", to_string(\$message.${WD}_ShareName));
end
EOF

# Acces a surveiller : on EXCLUT le bruit systeme (CdRom, C:\\Windows) et les
# comptes machine (\$). La portee fine est posee par les SACL cote serveur.
ensure_rule "omni-file-12-sensitive" <<EOF
rule "omni-file-12-sensitive"
when
  to_string(\$message.event_source) == "windows_security"
  AND to_long(\$message.event_id, 0) == 4663
  AND NOT ends_with(to_string(\$message.user), "\$")
  AND NOT contains(to_string(\$message.${WD}_ObjectName), "\\\\Device\\\\CdRom", true)
  AND NOT contains(to_string(\$message.${WD}_ObjectName), "C:\\\\Windows", true)
  AND NOT contains(to_string(\$message.${WD}_ObjectName), "\\\\AppData\\\\", true)
then
  set_field("alert_tag", "file_sensitive_access");
end
EOF

# Suppression de fichier sensible (AccessList contient DELETE %%1537) = signal
# exfil/ransomware. (4660 = objet supprime ; 4663+DELETE = tentative de suppression.)
ensure_rule "omni-file-12-delete" <<EOF
rule "omni-file-12-delete"
when
  to_string(\$message.event_source) == "windows_security"
  AND ( to_long(\$message.event_id, 0) == 4663 OR to_long(\$message.event_id, 0) == 4660 )
  AND NOT ends_with(to_string(\$message.user), "\$")
  AND ( contains(to_string(\$message.${WD}_AccessList), "%%1537", true)
     OR to_long(\$message.event_id, 0) == 4660 )
  AND NOT contains(to_string(\$message.${WD}_ObjectName), "C:\\\\Windows", true)
then
  set_field("alert_tag", "file_delete_sensible");
end
EOF

echo "==> [3/4] Pipeline 'OMNI - Audit fichiers' (stage 12) + connexion"
# Pipeline dedie a UN stage : s'il ne matche pas (event non-fichier), il s'arrete
# sans effet (rien apres) -> pas de halt-trap, et n'impacte pas les autres pipelines.
PL="$(ensure_pipeline "OMNI - Audit fichiers" <<'EOF'
pipeline "OMNI - Audit fichiers"
stage 12 match either
rule "omni-file-12-normalise"
rule "omni-file-12-sensitive"
rule "omni-file-12-delete"
end
EOF
)"
for ST in "OMNI - Windows Security" "OMNI - Windows autres"; do
  SID="$(get_stream_id "${ST}")"
  [[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL}" || warn "stream absent: ${ST}"
done

echo "==> [4/4] Termine."
cat <<'NOTE'

=== 59 termine. COTE SERVEURS DE FICHIERS (a faire par GPO ou en local) ===
1) Activer la sous-categorie d'audit (une seule fois) :
     auditpol /set /subcategory:"File System" /success:enable /failure:enable
   (option large, niveau partage - tres verbeux) :
     auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
2) Poser une SACL d'audit UNIQUEMENT sur les dossiers SENSIBLES (joyaux) - PowerShell :
     $p = "D:\Donnees\Clients"            # adapter au dossier sensible
     $acl = Get-Acl $p
     $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
       "Authenticated Users","Read,Write,Delete","ContainerInherit,ObjectInherit","None","Success")
     $acl.AddAuditRule($rule); Set-Acl $p $acl
   -> seuls les acces a CES dossiers generent du 4663 -> tag file_sensitive_access.
Verifier ensuite cote SIEM : recherche  alert_tag:file_sensitive_access
=== Relancer 13 (alerte acces de masse) + 14 (widget). ===
NOTE
