#!/bin/bash
# sync-deploye.sh est RETIRÉ (12/11/2026) : son étape « 2 bis » recopiait dans le dépôt les fichiers
# modifiés de la copie /root/omnitech-siem-setup, qui contient des versions anciennes (régressions).
# Utiliser à la place :
#   ./generer-manifeste.sh            (liste des fichiers en service suivis par le dépôt)
#   ./synchro-manifeste.sh            (état, comparaison SHA-256)
#   ./synchro-manifeste.sh --copier   (copie + scan bloquant, sans commit)
echo "sync-deploye.sh est retiré : utiliser ./synchro-manifeste.sh (voir l'en-tête de ce fichier)." >&2
exit 1
