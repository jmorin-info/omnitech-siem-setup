<#
.SYNOPSIS
  Set-OmniAudit-NinjaOne.ps1 - Applique la politique d'audit SIEM OMNITECH
  en LOCAL (sans GPO), pour les postes geres par NinjaOne. Idempotent, SYSTEM.

.DESCRIPTION
  Equivalent local de la GPO OMNI-AUDIT-Baseline (meme baseline CSV) :
    1. auditpol /restore de la baseline avancee (4624/4625, 4688, 4768/4769/4776,
       gestion comptes, 4662/5136, USB, NPS, PKI/AD CS, 1102...)
    2. ProcessCreationIncludeCmdLine = 1  (ligne de commande dans les 4688)
    3. PowerShell Script Block Logging = 1 (4104)
       [Module Logging 4103 NON active : trop verbeux, retire de la collecte SIEM]
    4. SCENoApplyLegacyAuditPolicy = 1 (force la politique avancee)
    5. Journal Security agrandi (defaut 2 Go), mode circulaire
  Verifie et journalise dans C:\ProgramData\OMNI-SIEM\audit.log.

  Deploiement NinjaOne : script PowerShell, execution SYSTEM, 64 bits, planifie
  quotidiennement (comme Deploy-SiemAgents-NinjaOne.ps1). Idempotent : rejouable.
  Sur un poste de domaine ou la GPO d'audit s'applique, la GPO prime au refresh
  (configuration identique : aucun conflit).

.NOTES
  Verif manuelle : auditpol /get /category:*  +  wevtutil gl Security
  Codes retour : 0 = OK, 1 = echec (details dans le transcript).
#>
[CmdletBinding()]
param(
  [int]$SecurityLogMB = 2048
)
$ErrorActionPreference = "Stop"
$Staging = "C:\ProgramData\OMNI-SIEM"
New-Item -ItemType Directory -Path $Staging -Force | Out-Null
Start-Transcript -Path (Join-Path $Staging "audit.log") -Append | Out-Null
$Fail = $false
function Step($m){ Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }

# Baseline auditpol (format auditpol /backup) - identique a windows/audit-baseline.csv
$AuditCsv = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Audit Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Kerberos Authentication Service,{0cce9242-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Kerberos Service Ticket Operations,{0cce9240-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Other Account Logon Events,{0cce9241-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit User Account Management,{0cce9235-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Computer Account Management,{0cce9236-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Security Group Management,{0cce9237-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Distribution Group Management,{0cce9238-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Application Group Management,{0cce9239-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Other Account Management Events,{0cce923a-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Process Termination,{0cce922c-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit DPAPI Activity,{0cce922d-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit PNP Activity,{0cce9248-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit RPC Events,{0cce922e-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Token Right Adjusted Events,{0cce924a-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Directory Service Access,{0cce923b-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Directory Service Changes,{0cce923c-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Directory Service Replication,{0cce923d-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Detailed Directory Service Replication,{0cce923e-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Logoff,{0cce9216-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Account Lockout,{0cce9217-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Special Logon,{0cce921b-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Other Logon/Logoff Events,{0cce921c-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Network Policy Server,{0cce9243-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Group Membership,{0cce9249-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit User / Device Claims,{0cce9247-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit IPsec Main Mode,{0cce9218-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit IPsec Quick Mode,{0cce9219-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit IPsec Extended Mode,{0cce921a-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit File Share,{0cce9224-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Detailed File Share,{0cce9244-69ae-11d9-bed3-505054503030},Failure,,2
,System,Audit File System,{0cce921d-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Registry,{0cce921e-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Kernel Object,{0cce921f-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit SAM,{0cce9220-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Certification Services,{0cce9221-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Application Generated,{0cce9222-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Handle Manipulation,{0cce9223-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Filtering Platform Packet Drop,{0cce9225-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Filtering Platform Connection,{0cce9226-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Other Object Access Events,{0cce9227-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Removable Storage,{0cce9245-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Central Policy Staging,{0cce9246-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Sensitive Privilege Use,{0cce9228-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Non Sensitive Privilege Use,{0cce9229-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Other Privilege Use Events,{0cce922a-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Audit Policy Change,{0cce922f-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Authentication Policy Change,{0cce9230-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Authorization Policy Change,{0cce9231-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit MPSSVC Rule-Level Policy Change,{0cce9232-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Filtering Platform Policy Change,{0cce9233-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Other Policy Change Events,{0cce9234-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Security State Change,{0cce9210-69ae-11d9-bed3-505054503030},Success,,1
,System,Audit Security System Extension,{0cce9211-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit System Integrity,{0cce9212-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit IPsec Driver,{0cce9213-69ae-11d9-bed3-505054503030},No Auditing,,0
,System,Audit Other System Events,{0cce9214-69ae-11d9-bed3-505054503030},No Auditing,,0
'@

try {
  # --- 1. Politique d'audit avancee (auditpol /restore) ----------------------
  $csvPath = Join-Path $Staging "omni-audit.csv"
  [System.IO.File]::WriteAllText($csvPath, $AuditCsv, (New-Object System.Text.UTF8Encoding($false)))
  Step "Application de la baseline d'audit (auditpol /restore)"
  $r = & auditpol.exe /restore /file:"$csvPath" 2>&1
  if ($LASTEXITCODE -ne 0) { throw "auditpol /restore KO : $r" }

  # --- 2-4. Cles registre ----------------------------------------------------
  function Set-Reg($Key,$Name,$Type,$Value){
    if (-not (Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
    New-ItemProperty -Path $Key -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    Step "reg: $Key\$Name = $Value"
  }
  Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" DWord 1
  Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" DWord 1
  Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" DWord 1

  # --- 5. Journal Security ----------------------------------------------------
  $bytes = $SecurityLogMB * 1MB
  Step "Journal Security -> $SecurityLogMB Mo (circulaire)"
  & wevtutil.exe sl Security /ms:$bytes /rt:false /ab:false
  if ($LASTEXITCODE -ne 0) { Step "ATTENTION: wevtutil sl Security a renvoye $LASTEXITCODE (journal verrouille par GPO ?)" }

  # --- Verification ----------------------------------------------------------
  $active = (& auditpol.exe /get /category:* | Select-String "Success").Count
  Step "Verif : $active sous-categories auditees (Success / Success+Failure)"
  $proc = (& auditpol.exe /get /subcategory:"Process Creation" | Select-String "Process Creation")
  Step ("Verif Process Creation: " + (($proc -join ' ') -replace '\s+',' '))
  $sz = (& wevtutil.exe gl Security | Select-String "maxSize")
  Step ("Verif Security log: " + (($sz -join ' ') -replace '\s+',' '))
  Step "Termine. Les 4624/4625/4688... vont desormais remonter dans Graylog."
}
catch {
  Step ("ERREUR : " + $_.Exception.Message); $Fail = $true
}
finally { Stop-Transcript | Out-Null }
if ($Fail) { exit 1 } else { exit 0 }
