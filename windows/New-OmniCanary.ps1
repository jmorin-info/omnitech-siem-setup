<#
.SYNOPSIS
  New-OmniCanary.ps1 - Cree un compte CANARI AD (leurre de detection d'intrusion).

.DESCRIPTION
  Un compte attractif (semble etre un compte de service SQL privilegie) mais
  SANS aucun privilege reel et JAMAIS utilise. Toute authentification,
  tentative ou requete Kerberos le concernant est detectee par le SIEM
  (alerte "OMNI - COMPTE CANARI touche") -> signal d'enumeration AD, brute
  force, Kerberoasting ou mouvement lateral, avec un taux de faux positifs
  quasi nul.

  Le compte :
   - mot de passe fort aleatoire (jamais communique, jamais utilise) ;
   - PasswordNeverExpires, CannotChangePassword ;
   - un SPN leurre (MSSQLSvc) -> piege le Kerberoasting (genere un 4769) ;
   - AUCUNE appartenance privilegiee (aucun risque si le mdp etait casse) ;
   - description credible pour l'attractivite.

  IMPORTANT : le SamAccountName DOIT correspondre a une ligne de
  lookups/canary-accounts.csv cote SIEM (defaut : svc_sql_adm). Si vous
  changez le nom ici, mettez aussi a jour le CSV et relancez 35-canary.sh.

.NOTES
  A executer sur un DC ou poste d'admin avec le module ActiveDirectory, en
  tant qu'admin habilite. Idempotent.
#>
[CmdletBinding()]
param(
  [string]$SamAccountName = "svc_sql_adm",
  [string]$DisplayName    = "SQL Service Admin",
  [string]$Description     = "Compte de service SQL (production) - ne pas desactiver",
  # Adapter l'OU a votre annuaire (doit exister) :
  [string]$OuPath         = "OU=Comptes_Service,OU=_Support,OU=Entreprise,DC=omnitech,DC=security",
  [string]$SpnHost        = "sql-prod.omnitech.security",
  [int]   $SpnPort        = 1433
)
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory

if (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue) {
  Write-Host "[=] Le compte canari '$SamAccountName' existe deja - rien a faire."
  return
}

# Mot de passe fort aleatoire (jamais affiche : le compte n'est jamais utilise)
$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$pwd = [Convert]::ToBase64String($bytes) + "!Aa9"
$sec = ConvertTo-SecureString $pwd -AsPlainText -Force

Write-Host "[*] Creation du compte canari '$SamAccountName' dans $OuPath"
New-ADUser -Name $DisplayName -SamAccountName $SamAccountName `
  -UserPrincipalName "$SamAccountName@omnitech.security" `
  -DisplayName $DisplayName -Description $Description `
  -Path $OuPath -AccountPassword $sec -Enabled $true `
  -PasswordNeverExpires $true -CannotChangePassword $true

# SPN leurre -> visible des comptes "kerberoastables", genere un 4769 si cible
$spn = "MSSQLSvc/${SpnHost}:${SpnPort}"
try {
  Set-ADUser -Identity $SamAccountName -ServicePrincipalNames @{Add=$spn}
  Write-Host "[+] SPN leurre ajoute : $spn"
} catch {
  Write-Host "[!] SPN non ajoute ($($_.Exception.Message)) - non bloquant"
}

# Verrou supplementaire : interdire toute ouverture de session interactive
# (un usage legitime accidentel devient impossible). Optionnel selon politique.
try {
  Set-ADUser -Identity $SamAccountName -Replace @{logonHours = ([byte[]](,0 * 21))}
  Write-Host "[+] Plages horaires de connexion = aucune (compte inactivable par design)"
} catch { Write-Host "[!] logonHours non applique - non bloquant" }

$u = Get-ADUser -Identity $SamAccountName -Properties Description,ServicePrincipalNames,Enabled
Write-Host ""
Write-Host "================ CANARI CREE ================"
Write-Host ("  SamAccountName : {0}" -f $u.SamAccountName)
Write-Host ("  Description    : {0}" -f $u.Description)
Write-Host ("  SPN            : {0}" -f ($u.ServicePrincipalNames -join ', '))
Write-Host ("  Active         : {0}" -f $u.Enabled)
Write-Host "============================================="
Write-Host "Cote SIEM : verifier que '$SamAccountName' est dans"
Write-Host "  lookups/canary-accounts.csv  (sinon l'ajouter + relancer 35-canary.sh)."
Write-Host "Test : tenter une connexion avec ce compte -> alerte SIEM en <2 min."
