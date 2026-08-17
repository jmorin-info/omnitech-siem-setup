<#
  Run-SealFix.ps1 — Exécution des correctifs SEAL -> SIEM (QA et OMEGA)
  ============================================================================
  À lancer SUR le serveur SEAL (bx-qa-seal-vm, puis bx-seal-omega) avec un
  compte ADMIN SQL. Enchaîne les scripts du dossier, dans l'ordre, en
  journalisant tout.

  CE QU'IL FAIT PAR DÉFAUT
     1. 01_fix_bit_columns.sql   -> APPLIQUE (débloque la détection ALM-001)
     2. 02_recon_topology.sql    -> LIT et enregistre la sortie dans un fichier
     4. 04_verification.sql      -> CONTRÔLE final (lecture seule)

  CE QU'IL NE FAIT PAS SANS VOUS
     3. 03_vw_SealZone_SIEM.sql  -> IGNORÉ par défaut. Ce script contient des
        hypothèses sur la hiérarchie SEAL qui doivent être confirmées par la
        sortie du 02 : le jouer à l'aveugle créerait une vue de zones FAUSSE
        (donc des alertes qui désignent le mauvais endroit) ou échouerait.
        Une fois le 03 ajusté, relancer avec -IncludeZones.

  Aucune donnée n'est modifiée : ces scripts ne créent que des vues (lecture
  seule). Tout est idempotent : relancer est sans effet de bord.

  PARAMÈTRES
    -Server <nom>    instance SQL (défaut : localhost)
    -Database <nom>  base (défaut : SEAL)
    -SqlUser <login> login admin SQL (ex. sa). Si omis -> authentification
                     Windows (-E) : votre session doit être sysadmin SQL.
    -Site <label>    étiquette pour nommer les fichiers de sortie (ex. QA,
                     OMEGA). Déduite du nom de la machine si omise.
    -OutDir <chemin> dossier des sorties (défaut : à côté du script)
    -IncludeZones    joue AUSSI le 03 (uniquement après l'avoir ajusté)
    -ModeleFonctionnel  extrait la STRUCTURE de la base pour la documentation
                     ISO 27001 (05_recon_fonctionnel.sql). Métadonnées et
                     paramétrage uniquement : aucune donnée personnelle lue.
                     À lancer une seule fois, sur OMEGA de préférence.
    -Complements     répond aux 3 questions ouvertes (06_recon_complements.sql) :
                     remplissage du pont badge, couverture du cache de zones,
                     piste T_PASSAGES. Comptages uniquement, lecture seule.
    -Force           n'invite pas à confirmer

  EXEMPLES
    # 1er passage, authentification Windows (session sysadmin) :
    powershell -ExecutionPolicy Bypass -File .\Run-SealFix.ps1 -Site QA

    # 1er passage, login SQL admin (mot de passe demandé, jamais en clair) :
    powershell -ExecutionPolicy Bypass -File .\Run-SealFix.ps1 -SqlUser sa -Site OMEGA

    # 2e passage, une fois 03_vw_SealZone_SIEM.sql ajusté avec la recon :
    powershell -ExecutionPolicy Bypass -File .\Run-SealFix.ps1 -Site QA -IncludeZones

  À RENVOYER : le fichier recon_<Site>_<date>.txt et verification_<Site>_<date>.txt

  CORRESPONDANCE DEPOT <-> LIVRAISON
     Ce lanceur est concu pour le dossier livre a l'exploitant (/tmp/sql), ou les
     fichiers sont numerotes dans l'ordre d'execution. Au depot ils portent leur
     nom d'origine :
       01_fix_bit_columns.sql   <-> seal/sql/03_vw_SealAlarms_SIEM.sql
       02_recon_topology.sql    <-> seal/sql/07_recon_topology.sql
       03_vw_SealZone_SIEM.sql  <-> seal/sql/07_vw_SealZone_SIEM.sql
       04_verification.sql      <-> (specifique livraison)
     Ne pas lancer ce script depuis seal/sql/ : il ne trouverait pas les noms
     attendus. Il s'utilise depuis le dossier livre.
  ============================================================================
#>
[CmdletBinding()]
param(
  [string]$Server   = "localhost",
  [string]$Database = "SEAL",
  [string]$SqlUser,
  [string]$Site,
  [string]$OutDir,
  [switch]$IncludeZones,
  [switch]$ModeleFonctionnel,
  [switch]$Complements,
  [switch]$Force
)

$ErrorActionPreference = "Stop"

# Un echec doit produire un message LISIBLE par un exploitant, pas une trace
# PowerShell. Et un code de sortie non nul, pour qu'un ordonnanceur le voie.
trap {
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Red
  Write-Host " ECHEC : $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "============================================================" -ForegroundColor Red
  Write-Host "Aucune donnee SEAL n'a ete modifiee : ces scripts ne creent que des vues." -ForegroundColor Yellow
  Write-Host "Corriger la cause ci-dessus puis relancer (le script est rejouable)." -ForegroundColor Yellow
  exit 1
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutDir) { $OutDir = $here }
if (-not $Site)   { $Site = $env:COMPUTERNAME }
$Site  = ($Site -replace '[^\w\-]', '_')
$stamp = Get-Date -Format "yyyyMMdd-HHmm"

if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
  throw "sqlcmd introuvable. Installer 'SQL Server Command Line Utilities', ou lancer ce script depuis une machine disposant de SSMS."
}
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

# --- Authentification admin (demandée UNE fois, jamais écrite sur disque) ----
$auth = @()
if ($SqlUser) {
  $sec  = Read-Host "Mot de passe SQL admin pour '$SqlUser'" -AsSecureString
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  $apwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  $auth = @("-U", $SqlUser, "-P", $apwd)
} else {
  $auth = @("-E")
}
# -b : sqlcmd renvoie un code d'erreur si le script echoue (sinon un echec passe
#      inapercu). -N -C : connexion chiffree, certificat auto-signe accepte.
$common = @("-S", $Server, "-N", "-C", "-b", "-V", "16")

function Invoke-SealScript {
  param(
    [Parameter(Mandatory)][string]$File,
    [string]$OutFile,
    [switch]$Tolerant   # un echec n'arrete pas le script (cas du 04)
  )
  $p = Join-Path $here $File
  if (-not (Test-Path $p)) { throw "Fichier manquant : $p" }
  Write-Host "  -> $File" -ForegroundColor Yellow
  if ($OutFile) {
    & sqlcmd @common -d $Database @auth -i $p -o $OutFile
  } else {
    & sqlcmd @common -d $Database @auth -i $p
  }
  if ($LASTEXITCODE -ne 0) {
    if ($Tolerant) {
      Write-Host "     (avertissement : code $LASTEXITCODE - voir la sortie ci-dessus)" -ForegroundColor DarkYellow
      return $false
    }
    throw "Echec sur $File (sqlcmd $LASTEXITCODE). Arret : rien n'a ete modifie par ce script (ce sont des vues)."
  }
  return $true
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Correctifs SEAL -> SIEM   ($Server / $Database)   site : $Site" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Ces scripts ne creent que des VUES : aucune donnee SEAL n'est modifiee," -ForegroundColor Green
Write-Host "aucune table n'est reecrite, et tout est rejouable sans effet de bord." -ForegroundColor Green
if (-not $Force) {
  $r = Read-Host "`nContinuer ? (o/N)"
  if ($r -ne "o" -and $r -ne "O") { Write-Host "Abandon a la demande." -ForegroundColor Red; return }
}

# --- 1. Correctif des colonnes bit (debloque ALM-001) -----------------------
Write-Host "`n-- 1/3  Correctif des qualificatifs d'alarme (bit -> varchar) --" -ForegroundColor Cyan
Write-Host "   IS_INHIBITED / IS_PRIORITY n'atteignaient jamais le SIEM :" -ForegroundColor Gray
Write-Host "   la detection ALM-001 (inhibition d'alarme) ne pouvait pas se declencher." -ForegroundColor Gray
Invoke-SealScript -File "01_fix_bit_columns.sql" | Out-Null
Write-Host "   OK : la vue vw_SealAlarms_SIEM emet desormais ces champs en texte." -ForegroundColor Green

# --- 2. Reconnaissance de la topologie (lecture seule) ----------------------
$reconOut = Join-Path $OutDir "recon_${Site}_${stamp}.txt"
Write-Host "`n-- 2/3  Reconnaissance de la hierarchie (aucune ecriture) --" -ForegroundColor Cyan
# -Tolerant : une RECONNAISSANCE explore une structure inconnue -- son echec est
# une INFORMATION (la structure differe de l'attendu), pas une panne. La rendre
# bloquante empechait la verification finale de tourner. Corrige le 16/07/2026
# apres echec sur OMEGA (severite 16 : la v1 du script codait la table en dur).
$reconOK = Invoke-SealScript -File "02_recon_topology.sql" -OutFile $reconOut -Tolerant
Write-Host "   Sortie enregistree : $reconOut" -ForegroundColor Green
if (-not $reconOK) {
  Write-Host "   La recon a signale une erreur : le fichier de sortie contient malgre" -ForegroundColor DarkYellow
  Write-Host "   tout ce qui a pu etre lu. Le renvoyer tel quel." -ForegroundColor DarkYellow
}

# --- 3. Vue des zones : UNIQUEMENT si demandee explicitement -----------------
Write-Host "`n-- 3/3  Vue des zones physiques --" -ForegroundColor Cyan
if ($IncludeZones) {
  $zonePath = Join-Path $here "03_vw_SealZone_SIEM.sql"
  $brut = Get-Content $zonePath -Raw
  # Deux garde-fous.
  # 1) Marqueur "<-- ajuster" encore present = fichier non adapte a la topologie
  #    reelle -> la vue creee serait fausse (zones erronees = alertes qui
  #    designent le mauvais lieu, pire que pas de zones du tout).
  # 2) Aucun CREATE = le fichier est une note explicative, pas un script. C'est
  #    l'etat depuis le 16/07/2026 : la vue a ete retiree, son hypothese ayant
  #    ete dementie par l'extraction du modele. Sans ce test, le lanceur
  #    "executerait" un commentaire et annoncerait un succes mensonger.
  if ($brut -notmatch '(?i)CREATE\s+(OR\s+ALTER\s+)?VIEW') {
    Write-Host "   IGNORE : 03_vw_SealZone_SIEM.sql ne contient aucune instruction." -ForegroundColor DarkYellow
    Write-Host "   La vue de zones a ete retiree : son modele de hierarchie etait faux" -ForegroundColor Gray
    Write-Host "   (cf. l'en-tete du fichier). Elle sera reecrite apres 06_recon_complements.sql." -ForegroundColor Gray
  }
  elseif ($brut -match '<--\s*ajuster') {
    Write-Host "   REFUS : 03_vw_SealZone_SIEM.sql contient encore des marqueurs '<-- ajuster'." -ForegroundColor Red
    Write-Host "   Il n'a donc pas ete adapte a la topologie reelle de ce SEAL." -ForegroundColor Red
    Write-Host "   Le jouer en l'etat creerait une vue de zones FAUSSE." -ForegroundColor Red
    Write-Host "   -> Renvoyer $reconOut pour que la vue soit ajustee, puis relancer." -ForegroundColor Yellow
  } else {
    Invoke-SealScript -File "03_vw_SealZone_SIEM.sql" | Out-Null
    Write-Host "   OK : vue vw_SealZone_SIEM creee + droit de lecture accorde au service." -ForegroundColor Green
  }
} else {
  Write-Host "   IGNORE (normal au premier passage)." -ForegroundColor DarkYellow
  Write-Host "   Ce script repose sur des hypotheses que seule la recon (etape 2) confirme." -ForegroundColor Gray
  Write-Host "   -> Renvoyer $reconOut, ajuster le 03, puis relancer avec -IncludeZones." -ForegroundColor Gray
}

# --- Extraction du modele fonctionnel (doc ISO 27001), a la demande ---------
# Metadonnees + parametrage uniquement : aucune donnee personnelle n'est lue.
# A ne lancer qu'UNE fois, sur OMEGA de preference (c'est la production).
if ($ModeleFonctionnel) {
  $modeleOut = Join-Path $OutDir "modele_SEAL_${Site}_${stamp}.txt"
  Write-Host "`n-- Extraction du modele fonctionnel (documentation ISO 27001) --" -ForegroundColor Cyan
  Write-Host "   Metadonnees et parametrage uniquement : aucun nom, badge, photo" -ForegroundColor Gray
  Write-Host "   ou mot de passe n'est lu (cf. en-tete de 05_recon_fonctionnel.sql)." -ForegroundColor Gray
  Invoke-SealScript -File "05_recon_fonctionnel.sql" -OutFile $modeleOut -Tolerant | Out-Null
  Write-Host "   Sortie enregistree : $modeleOut" -ForegroundColor Green
}

# --- Complements : les 3 questions ouvertes (lecture seule) -----------------
if ($Complements) {
  $compOut = Join-Path $OutDir "complements_${Site}_${stamp}.txt"
  Write-Host "`n-- Complements : 3 questions ouvertes --" -ForegroundColor Cyan
  Write-Host "   Comptages uniquement, aucune donnee personnelle lue." -ForegroundColor Gray
  Invoke-SealScript -File "06_recon_complements.sql" -OutFile $compOut -Tolerant | Out-Null
  Write-Host "   Sortie enregistree : $compOut" -ForegroundColor Green
}

# --- Verification finale (tolerante : le controle des zones echoue tant que
#     la vue n'existe pas, et c'est un resultat attendu, pas une panne) -------
$verifOut = Join-Path $OutDir "verification_${Site}_${stamp}.txt"
Write-Host "`n-- Verification --" -ForegroundColor Cyan
Invoke-SealScript -File "04_verification.sql" -OutFile $verifOut -Tolerant | Out-Null
if (Test-Path $verifOut) {
  Get-Content $verifOut | Write-Host
  Write-Host "   Sortie enregistree : $verifOut" -ForegroundColor Green
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " Termine sur $Site." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "A renvoyer :" -ForegroundColor Cyan
Write-Host "   $reconOut"
Write-Host "   $verifOut"
if ($ModeleFonctionnel -and $modeleOut) { Write-Host "   $modeleOut" }
if ($Complements -and $compOut) { Write-Host "   $compOut" }
Write-Host ""
Write-Host "Rappel : rejouer ce script sur l'AUTRE SEAL (QA et OMEGA doivent etre alignes)." -ForegroundColor Yellow
if (-not $IncludeZones) {
  Write-Host "Puis, une fois le 03 ajuste : -IncludeZones sur les deux sites." -ForegroundColor Yellow
}

if ($apwd) { $apwd = $null }
[GC]::Collect()
