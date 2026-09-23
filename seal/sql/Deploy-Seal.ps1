<#
  Deploy-Seal.ps1 — Déploiement AUTOMATISÉ côté SEAL (compte de service + DDL)
  ============================================================================
  À lancer SUR le serveur SEAL (BX-SEAL-OMEGA en prod, ou la QA), avec un login
  SQL ADMIN. Enchaîne, en une seule fois :
     1. Création du COMPTE DE SERVICE (mot de passe fort généré)
     2. DDL complet : rowversion (EVENEMENTS + 15 tables Audit) + 5 vues
        + 90_provision (verrouille le compte sur les vues UNIQUEMENT)
     3. Vérification (5 vues)
  Affiche à la fin le MOT DE PASSE du compte (à mettre dans Vaultwarden + le
  keystore Logstash côté SIEM). Idempotent.

  PARAMÈTRES
    -SqlUser <admin>   login admin SQL (ex. sa). Si omis -> auth Windows (-E),
                       votre session Windows doit alors être sysadmin SQL.
    -Force             ne pas demander de confirmation avant le DDL (sans
                       surveillance). Sinon une confirmation (o/N) est demandée
                       à cause de la réécriture de dbo.EVENEMENTS (voir NB PROD).

  NB PRODUCTION : l'étape rowversion sur dbo.EVENEMENTS RÉÉCRIT la table
  (opération de taille = nombre de lignes). Sur un gros EVENEMENTS de prod,
  prévoir une FENÊTRE DE MAINTENANCE. Si impossible, demander la variante sans
  réécriture (watermark EVEN_STORAGE_TIMESTAMP) — cf docs/ADD-SEAL-OMEGA.md.

  EXEMPLES
    # tout automatisé, auth SQL admin (mot de passe admin demandé une fois) :
    powershell -ExecutionPolicy Bypass -File .\Deploy-Seal.ps1 -SqlUser sa -Force
    # auth Windows (session sysadmin), zéro invite :
    powershell -ExecutionPolicy Bypass -File .\Deploy-Seal.ps1 -Force
  ============================================================================
#>
[CmdletBinding()]
param(
  [string]$Server   = "localhost",
  [string]$Database = "SEAL",
  [string]$SvcLogin = "svc_graylog_seal",
  [string]$SqlUser,
  [switch]$Force
)

$ErrorActionPreference = "Stop"
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$sqlDir = Join-Path $here "sql"
if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
  throw "sqlcmd introuvable. Installer 'SQL Server Command Line Utilities' (ou lancer depuis une machine avec SSMS)."
}
if (-not (Test-Path $sqlDir)) { throw "Dossier sql\ introuvable a cote de ce script : $sqlDir" }

# --- Auth admin (une seule fois) ---
$auth = @()
if ($SqlUser) {
  $sec  = Read-Host "Mot de passe SQL admin pour '$SqlUser'" -AsSecureString
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  $apwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
  $auth = @("-U", $SqlUser, "-P", $apwd)
} else {
  $auth = @("-E")
}
$common = @("-S", $Server, "-N", "-C", "-b", "-V", "16")

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Deploiement SEAL : compte de service + DDL  ($Server / $Database)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "NB : le DDL ajoute un rowversion a dbo.EVENEMENTS -> REECRITURE de la" -ForegroundColor Yellow
Write-Host "table (fenetre de maintenance recommandee sur un gros EVENEMENTS de prod)." -ForegroundColor Yellow
if (-not $Force) {
  $r = Read-Host "Continuer le deploiement ? (o/N)"
  if ($r -ne "o" -and $r -ne "O") { Write-Host "Abandon a la demande." -ForegroundColor Red; return }
}

# --- 1/2 : compte de service (mot de passe genere) ---
Add-Type -AssemblyName System.Web
$svcpwd = [System.Web.Security.Membership]::GeneratePassword(24, 4)
$esc = $svcpwd -replace "'", "''"
$sqlAcct = @"
SET NOCOUNT ON;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$SvcLogin')
    CREATE LOGIN [$SvcLogin] WITH PASSWORD = N'$esc', CHECK_POLICY = ON;
USE [$Database];
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$SvcLogin')
    CREATE USER [$SvcLogin] FOR LOGIN [$SvcLogin];
PRINT '[+] compte de service $SvcLogin pret';
"@
Write-Host "`n-- 1/2  Compte de service --" -ForegroundColor Cyan
$sqlAcct | sqlcmd @common -d master @auth
if ($LASTEXITCODE -ne 0) { throw "Echec creation du compte de service (sqlcmd $LASTEXITCODE)." }

# --- 2/2 : DDL dans l'ordre ---
$order = @(
  "01_rowver_evenements.sql", "01b_rowver_audit.sql",
  "02_vw_SealEvents_SIEM.sql", "03_vw_SealAlarms_SIEM.sql", "04_vw_SealAudit_SIEM.sql",
  "05_vw_SealIdentity_SIEM.sql", "06_vw_SealReev_SIEM.sql", "90_provision.sql"
)
Write-Host "`n-- 2/2  DDL (vues + rowversion + verrouillage) --" -ForegroundColor Cyan
foreach ($f in $order) {
  $p = Join-Path $sqlDir $f
  if (-not (Test-Path $p)) { throw "Fichier DDL manquant : $p" }
  Write-Host "  -> $f" -ForegroundColor Yellow
  & sqlcmd @common -d $Database @auth -i $p
  if ($LASTEXITCODE -ne 0) { throw "Echec DDL sur $f (sqlcmd $LASTEXITCODE). Arret." }
}

Write-Host "`n-- Verification --" -ForegroundColor Cyan
& sqlcmd @common -d $Database @auth -Q "SELECT name AS vue_SIEM FROM sys.views WHERE name LIKE 'vw_Seal%_SIEM' ORDER BY name;"

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " OK : compte cree, 5 vues creees, compte verrouille sur les vues." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "`nMOT DE PASSE DU COMPTE DE SERVICE (Vaultwarden + keystore SIEM, UNE seule fois) :" -ForegroundColor Yellow
Write-Host "    Login : $SvcLogin"
Write-Host "    Pass  : $svcpwd"
Write-Host "`nEtape suivante (cote SIEM 10.33.220.10) :" -ForegroundColor Cyan
Write-Host "  - ajouter au keystore Logstash : SEAL2_DB_SVC_USER='$SvcLogin' / SEAL2_DB_SVC_PWD"
Write-Host "  - deployer seal-omega.conf puis redemarrer logstash (cf docs/ADD-SEAL-OMEGA.md)."
$svcpwd = $null; if ($apwd) { $apwd = $null }
