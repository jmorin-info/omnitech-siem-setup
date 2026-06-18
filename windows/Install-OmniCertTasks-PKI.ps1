<#
.SYNOPSIS
  Install-OmniCertTasks-PKI.ps1 - Met en place, sur la PKI, la supervision des
  certificats du parc + (optionnel) la signature du CSR du SIEM. UN SEUL LANCEMENT.

.DESCRIPTION
  A executer sur la PKI (10.33.50.248), en administrateur. Le script :
    1. telecharge Get-OmniCertExpiry.ps1 et Sign-OmniSiemCsr.ps1 depuis le SIEM (/kit)
    2. cree le journal d'evenements Windows "OMNI-Certificats" (collecte par Winlogbeat)
    3. cree la tache planifiee "OMNI-CertExpiry" (quotidienne, SYSTEM) -> supervision
       de TOUS les certificats emis par la CA + magasin local, remontes au SIEM
    4. cree la tache planifiee "OMNI-SiemCertSign" (toutes les 20 min) -> signe le
       CSR depose par le SIEM avec le template WebServer (renouvellement auto du
       certificat console). Necessite un compte ayant le droit Enroll + acces au
       partage : le fournir via -SignerUser / -SignerPassword.
    5. lance une premiere supervision et verifie les prerequis.

  Idempotent : relancable (recree/maj les taches).

.PARAMETER WarnDays
  Seuil d'alerte d'expiration (jours). Defaut 60.

.PARAMETER SignerUser / -SignerPassword
  Compte (DOMAINE\user) executant la tache de signature. Doit avoir : droit
  Enroll sur le template WebServer + acces en ecriture au partage SIEM\certs.
  Si omis, la tache de signature N'EST PAS creee (la supervision, elle, l'est).

.NOTES
  Pre-requis : Winlogbeat doit etre installe sur la PKI (Install-OmniSiem-NinjaOne.ps1)
  pour que le journal OMNI-Certificats remonte au SIEM. Le script le verifie.
#>
[CmdletBinding()]
param(
  [string]$BaseUrl       = "https://bx-it-graylog-vm.omnitech.security/kit",
  [string]$InstallDir    = "C:\ProgramData\OMNI-SIEM",
  [int]   $WarnDays      = 60,
  [string]$SignerUser    = "",
  [string]$SignerPassword= ""
)
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Step($m){ Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

# --- 1. Telechargement des scripts depuis le SIEM ----------------------------
foreach ($f in @("Get-OmniCertExpiry.ps1","Sign-OmniSiemCsr.ps1")) {
  Step "Telechargement $f"
  Invoke-WebRequest -Uri "$BaseUrl/$f" -OutFile (Join-Path $InstallDir $f) -UseBasicParsing
}
$expiryPs = Join-Path $InstallDir "Get-OmniCertExpiry.ps1"
$signPs   = Join-Path $InstallDir "Sign-OmniSiemCsr.ps1"

# --- 2. Journal d'evenements dedie -------------------------------------------
if (-not [System.Diagnostics.EventLog]::SourceExists("OMNI-CertMonitor")) {
  New-EventLog -LogName "OMNI-Certificats" -Source "OMNI-CertMonitor"
  Step "Journal 'OMNI-Certificats' cree"
} else { Step "Journal 'OMNI-Certificats' deja present" }

# --- 3. Tache : supervision des certificats (SYSTEM, quotidienne) ------------
$actExp = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$expiryPs`" -WarnDays $WarnDays"
$trgExp = New-ScheduledTaskTrigger -Daily -At 8:00am
$prnExp = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "OMNI-CertExpiry" -Action $actExp -Trigger $trgExp `
  -Principal $prnExp -Description "Supervision expiration certificats -> SIEM" -Force | Out-Null
Step "Tache 'OMNI-CertExpiry' creee (quotidienne 08:00, SYSTEM)"

# --- 4. Tache : signature du CSR du SIEM (toutes les 20 min) ------------------
if ($SignerUser -and $SignerPassword) {
  $actSig = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$signPs`""
  $trgSig = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 20) -RepetitionDuration ([TimeSpan]::MaxValue)
  Register-ScheduledTask -TaskName "OMNI-SiemCertSign" -Action $actSig -Trigger $trgSig `
    -User $SignerUser -Password $SignerPassword -RunLevel Highest `
    -Description "Signe le CSR du SIEM (template WebServer) -> renouvellement auto" -Force | Out-Null
  Step "Tache 'OMNI-SiemCertSign' creee (toutes les 20 min, compte $SignerUser)"
} else {
  Step "Tache de signature NON creee (pas de -SignerUser/-SignerPassword)."
  Step "  -> relancer avec un compte ayant Enroll sur WebServer + acces au partage."
}

# --- 4bis. Activer l'audit de l'autorite de certification --------------------
# Sans ca, AUCUN evenement d'emission/refus/revocation (4886-4889/4870) n'est
# genere -> l'activite PKI ne remonte pas. AuditFilter 127 = tous les evenements
# de l'AC + sous-categorie "Certification Services".
Step "Activation de l'audit de l'autorite de certification (AuditFilter 127)"
& certutil -setreg CA\AuditFilter 127 2>&1 | Out-Null
# GUID de la sous-categorie "Certification Services" / "Services de certificats"
# (independant de la langue : le nom texte echoue sur un Windows FR -> 0x57)
& auditpol /set /subcategory:"{0cce9221-69ae-11d9-bed3-505054503030}" /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE -eq 0) {
  Restart-Service CertSvc -ErrorAction SilentlyContinue
  Step "Audit AC active (emissions/revocations tracees -> remontent au SIEM)"
} else {
  Step "[!] auditpol a echoue (code $LASTEXITCODE) - verifier les droits"
}

# --- 5. Premiere execution + verifications -----------------------------------
Step "Premiere supervision (peut prendre quelques secondes)..."
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $expiryPs -WarnDays $WarnDays

Write-Host ""
Write-Host "================== VERIFICATIONS =================="
# Winlogbeat present (sinon le journal ne remonte pas au SIEM)
if (Get-Service winlogbeat -ErrorAction SilentlyContinue) {
  Write-Host "  [OK] Winlogbeat installe (le journal OMNI-Certificats remontera au SIEM)"
} else {
  Write-Host "  [!!] Winlogbeat ABSENT -> lancer d'abord Install-OmniSiem-NinjaOne.ps1 sur la PKI,"
  Write-Host "       sinon les certificats ne remonteront pas au SIEM."
}
# Template WebServer disponible (pour la signature)
$tpl = (certutil -CATemplates 2>$null | Select-String -Pattern "OMS")
if ($tpl) { Write-Host "  [OK] Template OMS-WebServer publie sur l'AC" }
else { Write-Host "  [!?] Template OMS-WebServer non trouve via certutil -CATemplates (a verifier si signature voulue)" }
Write-Host "=================================================="
Write-Host ""
Write-Host "Termine. Cote SIEM : la page 'OMNI - SOC > Certificats' se remplira au prochain cycle."
Write-Host "Taches creees : Get-ScheduledTask -TaskName 'OMNI-*' | Format-Table TaskName,State"
