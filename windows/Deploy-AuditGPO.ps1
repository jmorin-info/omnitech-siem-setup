<#
.SYNOPSIS
  Deploy-AuditGPO.ps1 - Cree et configure la GPO "OMNI-AUDIT-Baseline"
  (a executer sur BX-AD-01-IT-VM / 10.33.50.250 en admin du domaine,
   modules GroupPolicy + ActiveDirectory requis = RSAT presents sur un DC).

.DESCRIPTION
  1. Cree la GPO (ou la met a jour) :
     - Strategie d'audit avancee : import du CSV audit-baseline.csv
       (copie dans SYSVOL + enregistrement de la CSE "Audit Policy Configuration")
     - Inclure la ligne de commande dans les 4688
     - PowerShell Script Block Logging + Module Logging (4103/4104)
     - Journal Security agrandi a 2 Go, retention "ecraser"
     - Force la strategie avancee (SCENoApplyLegacyAuditPolicy)
  2. Lie la GPO aux OU passees en parametre (sinon, affiche la commande).

.EXAMPLE
  # Sans parametre : lie a l'OU Entreprise (omnitech.security/Entreprise)
  # + Domain Controllers (les DS Access/DCSync ne s'auditent que sur les DC).
  .\Deploy-AuditGPO.ps1
  # Cible specifique :
  .\Deploy-AuditGPO.ps1 -LinkTo "OU=PILOTE,DC=omnitech,DC=security"

.NOTES
  Verification cote client apres gpupdate /force :
    auditpol /get /category:*
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
#>
[CmdletBinding()]
param(
  [string]   $GpoName  = "OMNI-AUDIT-Baseline",
  [string]   $CsvPath  = (Join-Path $PSScriptRoot "audit-baseline.csv"),
  [string[]] $LinkTo   = @("OU=Entreprise,DC=omnitech,DC=security",
                          "OU=Domain Controllers,DC=omnitech,DC=security")
)
$ErrorActionPreference = "Stop"
Import-Module GroupPolicy
Import-Module ActiveDirectory

if (-not (Test-Path $CsvPath)) { throw "CSV introuvable : $CsvPath" }
$Domain = Get-ADDomain

# --- 1. GPO -------------------------------------------------------------------
$Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $Gpo) {
  $Gpo = New-GPO -Name $GpoName -Comment "Audit avance + PowerShell logging - SIEM OMNITECH (genere par Deploy-AuditGPO.ps1)"
  Write-Host "[+] GPO creee : $GpoName ($($Gpo.Id))"
} else {
  Write-Host "[=] GPO existante : $GpoName ($($Gpo.Id)) - mise a jour"
}

# --- 2. CSV d'audit dans SYSVOL ------------------------------------------------
$AuditDir = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\{$($Gpo.Id)}\Machine\Microsoft\Windows NT\Audit"
New-Item -ItemType Directory -Path $AuditDir -Force | Out-Null
Copy-Item -Path $CsvPath -Destination (Join-Path $AuditDir "audit.csv") -Force
Write-Host "[+] audit.csv copie dans $AuditDir"

# --- 3. Enregistrer la CSE "Audit Policy Configuration" sur l'objet GPO ---------
#     (sans cela, le CSV n'est jamais applique par les clients)
$AuditCsePair = "[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]"
$GpoDn  = "CN={$($Gpo.Id)},CN=Policies,CN=System,$($Domain.DistinguishedName)"
$GpoObj = Get-ADObject -Identity $GpoDn -Properties gPCMachineExtensionNames
$Ext = $GpoObj.gPCMachineExtensionNames
if ([string]::IsNullOrEmpty($Ext)) { $Ext = "" }
if ($Ext -notlike "*F3CCC681-B74C-4060-9F26-CD84525DCA2A*") {
  # decoupe en blocs [..][..], ajoute le notre, retrie par 1er GUID (exigence du moteur GP)
  $Blocks = @()
  if ($Ext) { $Blocks = [regex]::Matches($Ext, "\[[^\]]+\]") | ForEach-Object { $_.Value } }
  $Blocks += $AuditCsePair
  $Sorted = $Blocks | Sort-Object { ($_ -replace "[\[\]]","").Substring(0,38) } -Unique
  Set-ADObject -Identity $GpoDn -Replace @{ gPCMachineExtensionNames = ($Sorted -join "") }
  Write-Host "[+] CSE Audit Policy enregistree (gPCMachineExtensionNames)"
} else {
  Write-Host "[=] CSE Audit Policy deja enregistree"
}

# --- 4. Cles registre (appliquees apres le CSV : bump auto de la version GPO) ---
function Set-Reg { param($Key,$Name,$Type,$Value)
  Set-GPRegistryValue -Name $GpoName -Key $Key -ValueName $Name -Type $Type -Value $Value | Out-Null
  Write-Host "    reg: $Key\$Name = $Value"
}
Write-Host "[+] Parametres registre :"
# 4688 : inclure la ligne de commande
Set-Reg "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        "ProcessCreationIncludeCmdLine_Enabled" DWord 1
# PowerShell : Script Block Logging (4104) + Module Logging (4103)
Set-Reg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        "EnableScriptBlockLogging" DWord 1
Set-Reg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        "EnableModuleLogging" DWord 1
Set-Reg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
        "*" String "*"
# Journal Security : 2 Go (valeur en Ko), ecrasement circulaire
Set-Reg "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize"   DWord 2097152
Set-Reg "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "Retention" String "0"
# Forcer la strategie d'audit AVANCEE (ignore l'ancienne strategie legacy)
Set-Reg "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" DWord 1

# --- 5. Liaison aux OU ----------------------------------------------------------
if ($LinkTo.Count -gt 0) {
  foreach ($OU in $LinkTo) {
    try {
      New-GPLink -Name $GpoName -Target $OU -LinkEnabled Yes -ErrorAction Stop | Out-Null
      Write-Host "[+] GPO liee a : $OU"
    } catch [System.ArgumentException] {
      Write-Host "[=] Lien deja existant : $OU"
    }
  }
} else {
  Write-Host ""
  Write-Host "GPO prete mais NON liee. Pilote recommande :" -ForegroundColor Yellow
  Write-Host "  New-GPLink -Name `"$GpoName`" -Target `"OU=PILOTE,$($Domain.DistinguishedName)`" -LinkEnabled Yes"
}

Write-Host ""
Write-Host "Termine. Sur un client pilote : gpupdate /force puis 'auditpol /get /category:*'"
Write-Host "Les sous-categories DS Access ne produisent des evenements que sur les DC (normal)."
