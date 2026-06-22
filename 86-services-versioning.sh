#!/usr/bin/env bash
# =============================================================================
# 86-services-versioning.sh - Rapatrie dans le depot 3 services deployes
#   MANUELLEMENT (binaire + units systemd absents du provisioning) :
#     - omni-cert-check     : verification expiration des certificats (hebdo)
#     - omni-cert-renew     : renouvellement cert console (CSR -> AD CS via SMB)
#     - omni-postboot-check : verification post-boot (/data TPM + services)
#   Cloture AC-2026-06-22-05 (reproductibilite / PRA). AS-IS, idempotent.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
[[ $EUID -eq 0 ]] || { echo "root requis"; exit 1; }
install -d /usr/local/sbin

# --- omni-cert-check ---
cat > /usr/local/sbin/omni-cert-check <<'OMNISBIN'
#!/usr/bin/env bash
# omni-cert-check - alerte avant expiration des certificats du SIEM (timer hebdo)
# Envoie un GELF (event_source=siem_cert) si un cert expire dans < SEUIL jours
# -> alerte "OMNI - Certificat SIEM expire bientot". Seuil par defaut 45 j.
set -u
SEUIL="${CERT_ALERT_DAYS:-45}"
GELF="http://127.0.0.1:12201/gelf"

check() {  # check <fichier> <label>
  local f="$1" label="$2" end days state action
  [ -f "$f" ] || return
  end="$(openssl x509 -in "$f" -noout -enddate 2>/dev/null | cut -d= -f2)"
  [ -z "$end" ] && return
  days=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
  echo "  ${label}: ${days} j (expire ${end})"
  # Etat courant : ok / proche / critique (sert au triage + couleur dashboard)
  if   [ "$days" -lt 15 ]; then state="critique"
  elif [ "$days" -lt "$SEUIL" ]; then state="proche"
  else state="ok"; fi
  # cert_expire_proche = declenche l'alerte (seulement si sous le seuil) ;
  # cert_status = telemetrie permanente (a CHAQUE run) -> la page Certificat
  # affiche toujours l'etat courant des certs SIEM, meme apres une purge.
  [ "$days" -lt "$SEUIL" ] && action="cert_expire_proche" || action="cert_status"
  curl -s -m 10 -X POST "$GELF" -H 'Content-Type: application/json' -d "{
    \"version\":\"1.1\",\"host\":\"bx-it-graylog-vm\",
    \"short_message\":\"certificat ${label} : ${days} jours restants (${state})\",
    \"_event_source\":\"siem_cert\",\"_event_action\":\"${action}\",
    \"_cert\":\"${label}\",\"_cert_days\":${days},\"_cert_state\":\"${state}\",\"_cert_expiry\":\"${end}\"}" >/dev/null 2>&1
}

echo "Verification des certificats SIEM (seuil ${SEUIL} j) :"
check /etc/nginx/ssl/graylog.crt           "console-nginx"
check /etc/graylog/certs/graylog.crt        "graylog-api"
check /etc/graylog/certs/omnitech-rootca.crt "root-ca"
OMNISBIN
chmod 755 /usr/local/sbin/omni-cert-check
cat > /etc/systemd/system/omni-cert-check.service <<'OMNIUNIT'
[Unit]
Description=Verification expiration des certificats SIEM
After=network-online.target graylog-server.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-cert-check
OMNIUNIT
cat > /etc/systemd/system/omni-cert-check.timer <<'OMNIUNIT'
[Unit]
Description=Verification hebdomadaire des certificats SIEM

[Timer]
OnCalendar=Mon *-*-* 07:30:00
Persistent=true

[Install]
WantedBy=timers.target
OMNIUNIT

# --- omni-cert-renew ---
cat > /usr/local/sbin/omni-cert-renew <<'OMNISBIN'
#!/usr/bin/env bash
# =============================================================================
# omni-cert-renew - Renouvellement automatique du certificat console (nginx)
# via CSR signe par l'AC AD CS (template WebServer), echange par partage SMB.
# -----------------------------------------------------------------------------
# SECURITE : la cle privee est generee et reste sur le SIEM ; seuls le CSR
# (public) et le certificat signe (public) transitent par le partage.
# Flux : SIEM depose graylog.csr -> un serveur Windows (Sign-OmniSiemCsr.ps1)
#        le signe et depose graylog-signed.crt -> le SIEM l'installe.
# Timer quotidien. Declenche le renouvellement RENEW_DAYS avant expiration.
# Statut en GELF (event_source=siem_cert) -> tracable + alerte.
# =============================================================================
set -uo pipefail
FQDN="bx-it-graylog-vm.omnitech.security"
CERT="/etc/nginx/ssl/graylog.crt"
KEY="/etc/nginx/ssl/graylog.key"
SMB="//10.33.50.5/Public"
SMBSUB="SIEM/certs"
CRED="/root/.smb-siem.cred"
MNT="/mnt/siem-certs"
WORK="/var/lib/omni-cert-renew"
RENEW_DAYS="${CERT_RENEW_DAYS:-30}"
GELF="http://127.0.0.1:12201/gelf"

gelf() { curl -s -m10 -X POST "$GELF" -H 'Content-Type: application/json' -d "{
  \"version\":\"1.1\",\"host\":\"bx-it-graylog-vm\",\"short_message\":\"cert-renew: $2\",
  \"_event_source\":\"siem_cert\",\"_event_action\":\"$1\"}" >/dev/null 2>&1 || true; }
cleanup() { mountpoint -q "$MNT" && umount "$MNT" 2>/dev/null || true; }
trap cleanup EXIT
mkdir -p "$WORK"; chmod 700 "$WORK"

# 1. Le cert expire-t-il bientot ? (sinon rien a faire)
end="$(openssl x509 -in "$CERT" -noout -enddate 2>/dev/null | cut -d= -f2)"
days=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
if [ "$days" -ge "$RENEW_DAYS" ]; then
  echo "Certificat valide ${days} j (> ${RENEW_DAYS}) - aucun renouvellement."
  exit 0
fi
echo "Certificat expire dans ${days} j -> procedure de renouvellement."

# 2. Monter le partage
mkdir -p "$MNT"
mountpoint -q "$MNT" || mount -t cifs "$SMB" "$MNT" -o "credentials=${CRED},vers=3.0" \
  || { gelf cert_renew_echec "montage SMB impossible"; echo "ERREUR montage"; exit 1; }
DIR="$MNT/$SMBSUB"; mkdir -p "$DIR"
SIGNED="$DIR/graylog-signed.crt"

# 3. Un certificat signe est-il deja revenu (depose par le serveur Windows) ?
if [ -f "$SIGNED" ] && [ -f "$WORK/graylog.key.new" ]; then
  cm="$(openssl x509 -in "$SIGNED" -noout -modulus 2>/dev/null | openssl md5)"
  km="$(openssl rsa  -in "$WORK/graylog.key.new" -noout -modulus 2>/dev/null | openssl md5)"
  if [ -n "$cm" ] && [ "$cm" = "$km" ]; then
    echo "Certificat signe valide (correspond a la cle en attente) -> installation."
    cp -a "$CERT" "${CERT}.bak-$(date +%F)"; cp -a "$KEY" "${KEY}.bak-$(date +%F)"
    install -m644 "$SIGNED" "$CERT"
    install -m600 "$WORK/graylog.key.new" "$KEY"
    if nginx -t 2>/dev/null; then
      systemctl reload nginx
      newend="$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)"
      rm -f "$SIGNED" "$DIR/graylog.csr" "$WORK/graylog.key.new"
      gelf cert_renew_ok "nouveau certificat installe (expire ${newend})"
      echo "OK : nouveau certificat installe, nginx recharge."
    else
      cp -a "${CERT}.bak-$(date +%F)" "$CERT"; cp -a "${KEY}.bak-$(date +%F)" "$KEY"
      gelf cert_renew_echec "nginx -t a echoue, rollback"
      echo "ERREUR nginx -t, rollback effectue."; exit 1
    fi
    exit 0
  else
    echo "Certificat signe present mais ne correspond pas a la cle en attente (ignore)."
  fi
fi

# 4. Pas de cert signe : generer cle+CSR et le deposer (si pas deja en attente)
if [ -f "$DIR/graylog.csr" ] && [ -f "$WORK/graylog.key.new" ]; then
  echo "CSR deja depose, en attente de signature par le serveur Windows."
  gelf cert_renew_attente "CSR en attente de signature (cert expire ${days}j)"
else
  # SAN complet : FQDN + nom court + IP (sinon perdus a chaque renouvellement ->
  # nginx/Beats casseraient sur acces par IP ou nom court). IP surchargeable.
  CERT_SAN_IP="${CERT_SAN_IP:-10.33.220.10}"
  SAN="DNS:${FQDN},DNS:${FQDN%%.*},IP:${CERT_SAN_IP}"
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$WORK/graylog.key.new" -out "$DIR/graylog.csr" \
    -subj "/CN=${FQDN}" -addext "subjectAltName=${SAN}" 2>/dev/null
  chmod 600 "$WORK/graylog.key.new"
  gelf cert_renew_csr "CSR depose sur le partage, en attente de signature (cert expire ${days}j)"
  echo "CSR genere et depose : ${SMB}/${SMBSUB}/graylog.csr"
fi
OMNISBIN
chmod 755 /usr/local/sbin/omni-cert-renew
cat > /etc/systemd/system/omni-cert-renew.service <<'OMNIUNIT'
[Unit]
Description=Renouvellement automatique du certificat console (CSR -> AD CS via SMB)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-cert-renew
OMNIUNIT
cat > /etc/systemd/system/omni-cert-renew.timer <<'OMNIUNIT'
[Unit]
Description=Verification quotidienne du renouvellement de certificat SIEM

[Timer]
OnCalendar=*-*-* 06:00:00
Persistent=true
RandomizedDelaySec=600

[Install]
WantedBy=timers.target
OMNIUNIT

# --- omni-postboot-check ---
cat > /usr/local/sbin/omni-postboot-check <<'OMNISBIN'
#!/usr/bin/env bash
# omni-postboot-check - verification automatique au demarrage du SIEM.
#   Confirme que /data s'est dechiffre tout seul (TPM2) et que les services sont up.
#   Journalise /var/log/omni-postboot.log + emet un GELF (event_source=siem_boot).
#   Lance par omni-postboot-check.service (oneshot, a chaque boot).
sleep 45   # laisser les services finir de demarrer
CD=$([ -e /dev/mapper/cryptdata ] && echo actif || echo ABSENT)
DM=$(mountpoint -q /data && echo monte || echo NON-MONTE)
MO=$(systemctl is-active mongod); OS=$(systemctl is-active opensearch); GL=$(systemctl is-active graylog-server)
CL=$(curl -s --max-time 10 http://127.0.0.1:9200/_cluster/health 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])' 2>/dev/null || echo injoignable)
VERDICT="OK"
[ "$DM" = "NON-MONTE" ] && VERDICT="DEGRADE: /data non monte (TPM ?) -> cryptsetup open + passphrase"
[ "$GL" != "active" ] && VERDICT="DEGRADE: graylog=$GL"
printf '%s | cryptdata=%s /data=%s mongod=%s opensearch=%s graylog=%s cluster=%s | %s\n' \
  "$(date -u +%FT%TZ)" "$CD" "$DM" "$MO" "$OS" "$GL" "$CL" "$VERDICT" >> /var/log/omni-postboot.log
# GELF best-effort (ne marche que si graylog est up).
# Succes -> evenement de SANTE (health_type=boot_ok) SANS alert_tag : un boot reussi
# est un signal POSITIF, il ne doit pas polluer le namespace de detection (alert_tag).
# Echec -> alert_tag=siem_job_fail (vraie alerte : faute interne SIEM, alerte existante).
# Dans les deux cas le statut reste tracable via event_source=siem_boot + boot_verdict.
if [ "$VERDICT" = "OK" ]; then TAGF="\"_health_type\":\"boot_ok\""; else TAGF="\"_alert_tag\":\"siem_job_fail\""; fi
curl -s -m 10 -X POST http://127.0.0.1:12201/gelf -H 'Content-Type: application/json' \
  -d "{\"version\":\"1.1\",\"host\":\"bx-it-graylog-vm\",\"short_message\":\"SIEM post-boot: ${VERDICT} (/data=${DM}, graylog=${GL}, cluster=${CL})\",\"_event_source\":\"siem_boot\",${TAGF},\"_boot_verdict\":\"${VERDICT}\"}" >/dev/null 2>&1 || true
OMNISBIN
chmod 755 /usr/local/sbin/omni-postboot-check
cat > /etc/systemd/system/omni-postboot-check.service <<'OMNIUNIT'
[Unit]
Description=OMNI SIEM - verification post-boot (/data TPM + services)
After=graylog-server.service opensearch.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/omni-postboot-check

[Install]
WantedBy=multi-user.target
OMNIUNIT

systemctl daemon-reload
systemctl enable --now omni-cert-check.timer omni-cert-renew.timer omni-postboot-check.service
echo "  [86] cert-check / cert-renew / postboot-check versionnes + actifs"
