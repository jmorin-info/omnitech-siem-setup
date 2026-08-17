<#
  Create-SealServiceAccount.ps1
  ============================================================================
  Cree le COMPTE DE SERVICE SQL (lecture seule) utilise par la collecte
  SEAL -> SIEM. A lancer SUR le serveur SEAL (BX-SEAL-OMEGA en prod, ou la QA),
  avec un login SQL ADMIN (sysadmin, ou securityadmin + db_owner sur SEAL).

  Etape 1 du deploiement d'un SEAL. Ensuite : Run-SealDDL.ps1 (cree les vues et
  VERROUILLE ce compte sur les vues uniquement).

  SECURITE : le mot de passe du compte de service n'est JAMAIS ecrit sur disque
  ni passe en ligne de commande. Il est saisi masque (ou genere), puis transmis
  a sqlcmd via l'entree standard (stdin). Idempotent (login/user crees si absents).

  EXEMPLES
    # mot de passe saisi de facon masquee, auth admin SQL :
    powershell -ExecutionPolicy Bypass -File .\Create-SealServiceAccount.ps1 -SqlUser sa

    # generer un mot de passe fort (affiche UNE fois, a stocker dans Vaultwarden) :
    .\Create-SealServiceAccount.ps1 -SqlUser sa -GeneratePassword

    # auth Windows (si votre session est sysadmin SQL) :
    .\Create-SealServiceAccount.ps1
  ============================================================================
#>
[CmdletBinding()]
param(
  [string]$Server           = "localhost",
  [string]$Database         = "SEAL",
  [string]$SvcLogin         = "svc_graylog_seal",
  [string]$SqlUser,                     # login admin ; si absent -> auth Windows (-E)
  [switch]$GeneratePassword
)

$ErrorActionPreference = "Stop"
if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
  throw "sqlcmd introuvable. Installer 'SQL Server Command Line Utilities' (ou lancer depuis une machine avec SSMS)."
}

# --- Authentification ADMIN ---
$auth = @()
if ($SqlUser) {
  $sec  = Read-Host "Mot de passe SQL admin pour '$SqlUser'" -AsSecureString
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  $apwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
  $auth = @("-U", $SqlUser, "-P", $apwd)
} else {
  $auth = @("-E")   # Windows trusted : votre compte doit etre sysadmin SQL
}

# --- Mot de passe du COMPTE DE SERVICE ---
if ($GeneratePassword) {
  Add-Type -AssemblyName System.Web
  $svcpwd = [System.Web.Security.Membership]::GeneratePassword(24, 4)   # 24 car., >=4 speciaux
} else {
  $sec2 = Read-Host "NOUVEAU mot de passe pour '$SvcLogin' (respecter la politique AD/SQL)" -AsSecureString
  $b2   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec2)
  $svcpwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto($b2)
}
$esc = $svcpwd -replace "'", "''"   # echappement pour le litteral T-SQL

# --- SQL idempotent (login serveur + user base) ---
$sql = @"
SET NOCOUNT ON;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$SvcLogin')
BEGIN
    CREATE LOGIN [$SvcLogin] WITH PASSWORD = N'$esc', CHECK_POLICY = ON;
    PRINT '[+] LOGIN $SvcLogin cree';
END
ELSE PRINT '[=] LOGIN $SvcLogin existe deja (mot de passe inchange)';
USE [$Database];
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$SvcLogin')
BEGIN
    CREATE USER [$SvcLogin] FOR LOGIN [$SvcLogin];
    PRINT '[+] USER $SvcLogin cree dans [$Database]';
END
ELSE PRINT '[=] USER $SvcLogin existe deja dans [$Database]';
"@

Write-Host "== Creation du compte de service '$SvcLogin' sur $Server/$Database ==" -ForegroundColor Cyan
# stdin : le mot de passe ne transite ni par la ligne de commande ni par un fichier
$sql | sqlcmd -S $Server -d master -N -C -b @auth
if ($LASTEXITCODE -ne 0) { throw "Echec creation compte (sqlcmd exit $LASTEXITCODE)." }

Write-Host ""
Write-Host "Compte de service pret. Prochaines etapes :" -ForegroundColor Green
Write-Host "  1) .\Run-SealDDL.ps1 -SqlUser $SqlUser   (cree les vues + verrouille le compte sur les vues)"
Write-Host "  2) Transmettre le mot de passe a l'admin SIEM -> keystore Logstash"
Write-Host "     (cles SEAL2_DB_SVC_USER='$SvcLogin' / SEAL2_DB_SVC_PWD pour BX-SEAL-OMEGA)."
if ($GeneratePassword) {
  Write-Host ""
  Write-Host "MOT DE PASSE GENERE (a stocker dans Vaultwarden - affiche UNE seule fois) :" -ForegroundColor Yellow
  Write-Host "    $svcpwd"
}
# nettoyage best-effort des variables sensibles
$svcpwd = $null; if ($apwd) { $apwd = $null }
