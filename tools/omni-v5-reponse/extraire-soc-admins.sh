#!/bin/sh
# omni-v5-reponse : ExecStartPre (root) - extrait SEULEMENT la clé SOC_ADMINS de
# /etc/default/omni-mobile (qui contient des secrets) vers /run/omni-v5-reponse/soc_admins.
umask 022
v=$(grep -E '^[[:space:]]*SOC_ADMINS[[:space:]]*=' /etc/default/omni-mobile 2>/dev/null | tail -n 1 \
    | sed 's/^[^=]*=//' | tr -cd 'A-Za-z0-9,._-')
printf '%s\n' "$v" > /run/omni-v5-reponse/soc_admins
chmod 644 /run/omni-v5-reponse/soc_admins
exit 0
