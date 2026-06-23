#!/usr/bin/env bash
# =============================================================================
# kit/linux-omni.sh - A DEPLOYER SUR CHAQUE SERVEUR LINUX (Debian) OMNITECH.
#   Forward des logs d'authentification + auditd vers le SIEM Graylog (Syslog TCP 1519).
#   Usage : sudo ./linux-omni.sh <IP_DU_SIEM>     (ex: sudo ./linux-omni.sh 10.33.220.10)
# =============================================================================
set -euo pipefail
SIEM_IP="${1:?Usage: $0 <IP_DU_SIEM>}"
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }

echo "==> [1/3] rsyslog : forward auth/authpriv/sudo/sshd/useradd -> ${SIEM_IP}:1519/TCP"
cat > /etc/rsyslog.d/60-omni-forward.conf <<EOF
# OMNITECH SIEM forward (auth + audit) - genere par linux-omni.sh
\$ActionQueueType LinkedList
\$ActionQueueFileName omni_fwd
\$ActionResumeRetryCount -1
\$ActionQueueSaveOnShutdown on
if (\$syslogfacility-text == "authpriv" or \$syslogfacility-text == "auth" or \$programname == "sudo" or \$programname == "su" or \$programname == "sshd" or \$programname == "useradd" or \$programname == "usermod" or \$programname == "groupadd" or \$programname startswith "audit") then {
    action(type="omfwd" target="${SIEM_IP}" port="1519" protocol="tcp"
           TCP_Framing="octet-counted" KeepAlive="on" action.resumeRetryCount="-1"
           queue.type="LinkedList" queue.saveOnShutdown="on")
}
EOF
systemctl restart rsyslog && echo "    rsyslog rechargé"

echo "==> [2/3] auditd : surveillance des fichiers sensibles (identite/privileges)"
if ! command -v auditctl >/dev/null 2>&1; then apt-get install -y auditd >/dev/null 2>&1 || echo "    (installer auditd manuellement)"; fi
cat > /etc/audit/rules.d/omni.rules <<'EOF'
# OMNITECH - surveillance fichiers sensibles (cles = omni_*)
-w /etc/passwd -p wa -k omni_passwd
-w /etc/shadow -p wa -k omni_shadow
-w /etc/sudoers -p wa -k omni_sudoers
-w /etc/sudoers.d/ -p wa -k omni_sudoers
-w /root/.ssh/ -p wa -k omni_sshkeys
-w /etc/ssh/sshd_config -p wa -k omni_sshkeys
EOF
augenrules --load 2>/dev/null || service auditd restart 2>/dev/null || true
# relais des events auditd vers syslog (pour qu'ils partent via rsyslog)
if [[ -f /etc/audit/plugins.d/syslog.conf ]]; then
  sed -i 's/^active = no/active = yes/' /etc/audit/plugins.d/syslog.conf 2>/dev/null || true
  service auditd restart 2>/dev/null || true
fi
echo "    règles auditd chargées (clés omni_passwd/shadow/sudoers/sshkeys)"

echo "==> [3/3] Test : envoi d'un message au SIEM"
logger -p authpriv.info -t omni-test "kit linux-omni deploye depuis $(hostname)"
echo "=== Kit deploye. Verifier dans la console SOC (stream 'OMNI - Linux') que $(hostname) remonte. ==="
