#!/usr/bin/env bash
# =============================================================================
# kit/install.sh - Enrolement SIEM OMNITECH (Linux), STANDALONE & idempotent.
#
#   One-liner :
#     curl -fsSL https://bx-it-graylog-vm.omnitech.security/kit/install.sh \
#       | sudo bash -s -- 10.33.220.10
#   (le « -- » separe les options de bash des ARGUMENTS du script ; $1 = SIEM)
#
#   Converge un hote Linux vers l'etat cible et VERIFIE tout :
#     0. prerequis : root, distro (apt/dnf/yum/zypper), connectivite SIEM:1519
#     1. paquets : rsyslog, auditd, logger (installes seulement si absents)
#     2. forward rsyslog auth/sudo/sshd/auditd -> SIEM:1519/TCP (idempotent par contenu)
#     3. auditd : surveillance fichiers sensibles (cles omni_passwd/shadow/sudoers/sshkeys)
#     4. test d'emission + re-test TCP ; resume [OK]/[KO] par composant ; exit 0/1
#
#   Reprend la logique de kit/linux-omni.sh en l'durcissant (multi-distro, checks,
#   resume). Relancable en boucle sans effet de bord.
# =============================================================================
set -uo pipefail
SIEM_IP="${1:-10.33.220.10}"
PORT=1519
declare -A R                                   # R[composant] = "OK ..." | "KO ..."
ok(){ R["$1"]="OK $2"; }
ko(){ R["$1"]="KO $2"; }
log(){ printf '==> %s\n' "$*"; }

# --- 0. PREREQUIS ------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then echo "[KO] root requis : relancez avec sudo"; exit 1; fi
if   command -v apt-get >/dev/null 2>&1; then PM=apt;    INSTALL="apt-get install -y -q";     AUDIT_PKG=auditd
elif command -v dnf     >/dev/null 2>&1; then PM=dnf;    INSTALL="dnf install -y -q";         AUDIT_PKG=audit
elif command -v yum     >/dev/null 2>&1; then PM=yum;    INSTALL="yum install -y -q";         AUDIT_PKG=audit
elif command -v zypper  >/dev/null 2>&1; then PM=zypper; INSTALL="zypper -nq install";        AUDIT_PKG=audit
else echo "[KO] gestionnaire de paquets non supporte (ni apt/dnf/yum/zypper)"; exit 1; fi
[[ $PM == apt ]] && LOGGER_PKG=bsdutils || LOGGER_PKG=util-linux
log "distro=$PM | SIEM=$SIEM_IP:$PORT | host=$(hostname)"

# connectivite AVANT (bash /dev/tcp : aucune dependance type nc)
if timeout 4 bash -c ">/dev/tcp/$SIEM_IP/$PORT" 2>/dev/null; then ok net "TCP $SIEM_IP:$PORT atteignable"
else ko net "TCP $SIEM_IP:$PORT injoignable (firewall/VLAN/policy ?) - la file rsyslog rejouera"; fi

# --- 1. PAQUETS --------------------------------------------------------------
need(){ command -v "$1" >/dev/null 2>&1 || { log "install $2"; $INSTALL "$2" >/dev/null 2>&1 || true; }; }
need rsyslogd "rsyslog"
command -v auditctl >/dev/null 2>&1 || { log "install $AUDIT_PKG"; $INSTALL "$AUDIT_PKG" >/dev/null 2>&1 || true; }
need logger "$LOGGER_PKG"
if command -v rsyslogd >/dev/null 2>&1; then ok pkg "rsyslog/auditd/logger en place"
else ko pkg "rsyslog absent (installation impossible)"; fi

# --- 2. FORWARD rsyslog (idempotent par contenu) -----------------------------
CONF=/etc/rsyslog.d/60-omni-forward.conf
read -r -d '' NEW <<EOF || true
# OMNITECH SIEM forward (auth + audit) - genere par kit/install.sh
\$ActionQueueType LinkedList
\$ActionQueueFileName omni_fwd
\$ActionResumeRetryCount -1
\$ActionQueueSaveOnShutdown on
if (\$syslogfacility-text == "authpriv" or \$syslogfacility-text == "auth" or \$programname == "sudo" or \$programname == "su" or \$programname == "sshd" or \$programname == "useradd" or \$programname == "usermod" or \$programname == "groupadd" or \$programname startswith "audit") then {
    action(type="omfwd" target="$SIEM_IP" port="$PORT" protocol="tcp"
           TCP_Framing="octet-counted" KeepAlive="on" action.resumeRetryCount="-1"
           queue.type="LinkedList" queue.saveOnShutdown="on")
}
EOF
if [[ "$(cat "$CONF" 2>/dev/null)" != "$NEW" ]]; then
  printf '%s\n' "$NEW" > "$CONF"
  if systemctl restart rsyslog 2>/dev/null || service rsyslog restart 2>/dev/null; then ok rsyslog "forward applique + reload"
  else ko rsyslog "ecrit mais reload KO"; fi
else ok rsyslog "deja a jour (inchange)"; fi

# --- 3. auditd (memes regles que linux-omni.sh ; idempotent) -----------------
if command -v auditctl >/dev/null 2>&1; then
  mkdir -p /etc/audit/rules.d
  cat > /etc/audit/rules.d/omni.rules <<'EOF'
# OMNITECH - surveillance fichiers sensibles (cles = omni_*)
-w /etc/passwd -p wa -k omni_passwd
-w /etc/shadow -p wa -k omni_shadow
-w /etc/sudoers -p wa -k omni_sudoers
-w /etc/sudoers.d/ -p wa -k omni_sudoers
-w /root/.ssh/ -p wa -k omni_sshkeys
-w /etc/ssh/sshd_config -p wa -k omni_sshkeys
EOF
  augenrules --load >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true
  # relais des events auditd vers syslog (pour qu'ils partent via rsyslog)
  if [[ -f /etc/audit/plugins.d/syslog.conf ]]; then
    sed -i 's/^active = no/active = yes/' /etc/audit/plugins.d/syslog.conf 2>/dev/null || true
    service auditd restart >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 || true
  fi
  if auditctl -l 2>/dev/null | grep -q omni_; then ok auditd "regles omni_* chargees"
  else ko auditd "regles ecrites mais non actives (auditd ?)"; fi
else ko auditd "auditctl absent (paquet $AUDIT_PKG non installe)"; fi

# --- 4. TEST D'EMISSION ------------------------------------------------------
logger -p authpriv.info -t omni-test "kit install.sh deploye depuis $(hostname)" 2>/dev/null \
  && ok test "message de test emis" || ko test "logger indisponible"

# --- RESUME ------------------------------------------------------------------
echo
echo "================ RESUME OMNI-SIEM ($(hostname)) ================"
FAIL=0
for k in net pkg rsyslog auditd test; do
  printf '  %-9s : %s\n' "$k" "${R[$k]:-? non execute}"
  [[ "${R[$k]:-}" == KO* ]] && FAIL=1
done
echo "  -> Verifier dans /soc (page Reseau & Infra / stream 'OMNI - Linux')"
echo "     que $(hostname) remonte (linux_ssh_fail / linux_sudo_root sur activite reelle)."
echo "==============================================================="
exit $FAIL
