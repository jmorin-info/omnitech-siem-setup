#!/bin/bash
# Retour SIEM v5 chantier 1 (27/11/2026) : supprime PAR NOM le pipeline « OMNI v5 - Detections AD et M365 »,
# les regles omni-v5-ad-* / omni-v5-m365-* et les definitions « OMNI v5 - AD » / « OMNI v5 - M365 ». Rien d'autre.
# A blanc : bash retour.sh --simuler
cd /root/omni-v5-ad || exit 1
if [ "$1" = "--simuler" ]; then python3 -I v5_ad_build.py --retour-simuler; else python3 -I v5_ad_build.py --retour; fi
