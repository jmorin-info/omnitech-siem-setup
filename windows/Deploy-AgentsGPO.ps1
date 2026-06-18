<#
.SYNOPSIS
  Deploy-AgentsGPO.ps1 - Deploiement DOMAINE ENTIER de Sysmon + Winlogbeat
  via GPO (sans NinjaOne). A executer sur BX-AD-01-IT-VM en admin du domaine.

.DESCRIPTION
  Cree la GPO "OMNI-SIEM-Agents" qui pousse sur chaque ordinateur cible une
  TACHE PLANIFIEE (Group Policy Preferences) executee en SYSTEM :
    - au demarrage (delai 5 min, le temps que le reseau monte)
    - + tous les jours a 12:00 avec delai aleatoire 2 h (lisse la charge
      sur NETLOGON et rattrape les machines jamais redemarrees)
  La tache lance :  powershell -ExecutionPolicy Bypass -File
                    \\<domaine>\NETLOGON\SIEM\Deploy-SysmonWinlogbeat.ps1
  Ce script (deja dans le kit) est idempotent : installation, mise a jour de
  conf, ou rien si tout est conforme. Donc la GPO = canal de deploiement ET
  de maintenance (pousser une nouvelle conf = remplacer le fichier dans
  NETLOGON\SIEM, les machines convergent en < 24 h).

  Prerequis : avoir rempli \\<domaine>\NETLOGON\SIEM (cf. README-WINDOWS §0) :
    Sysmon64.exe, sysmonconfig-omnitech.xml, winlogbeat-oss-<ver>-...zip,
    winlogbeat.yml, omnitech-rootca.pem, Deploy-SysmonWinlogbeat.ps1

.EXAMPLE
  # Sans parametre : lie a l'OU Entreprise (omnitech.security/Entreprise)
  .\Deploy-AgentsGPO.ps1
  # Pilote d'abord si souhaite :
  .\Deploy-AgentsGPO.ps1 -LinkTo "OU=PILOTE,DC=omnitech,DC=security"

.NOTES
  Verification cote client (apres gpupdate /force + ~5 min ou 12h00) :
    Get-ScheduledTask "OMNI-SIEM-Deploy" | Get-ScheduledTaskInfo
    Get-Service Sysmon64, winlogbeat
    C:\ProgramData\OMNI-SIEM\deploy.log
#>
[CmdletBinding()]
param(
  [string]   $GpoName = "OMNI-SIEM-Agents",
  [string[]] $LinkTo  = @("OU=Entreprise,DC=omnitech,DC=security"),
  [string]   $DeployScript = "Deploy-SysmonWinlogbeat.ps1"
)
$ErrorActionPreference = "Stop"
Import-Module GroupPolicy
Import-Module ActiveDirectory

$Domain = Get-ADDomain
$Share  = "\\$($Domain.DNSRoot)\NETLOGON\SIEM"

# --- 0. Sanity check du point de distribution -----------------------------------
$Required = @("Sysmon64.exe","sysmonconfig-omnitech.xml","winlogbeat.yml",
              "omnitech-rootca.pem",$DeployScript)
$Missing = $Required | Where-Object { -not (Test-Path (Join-Path $Share $_)) }
if (-not (Get-ChildItem "$Share\winlogbeat-oss-*-windows-x86_64.zip" -ErrorAction SilentlyContinue)) {
  $Missing += "winlogbeat-oss-<version>-windows-x86_64.zip"
}
if ($Missing) {
  Write-Warning "Fichiers manquants dans $Share :"
  $Missing | ForEach-Object { Write-Warning "  - $_" }
  throw "Completer NETLOGON\SIEM avant de deployer (README-WINDOWS §0)."
}
Write-Host "[+] Point de distribution OK : $Share"

# --- 1. GPO ----------------------------------------------------------------------
$Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $Gpo) {
  $Gpo = New-GPO -Name $GpoName -Comment "Deploiement Sysmon+Winlogbeat domaine entier - SIEM OMNITECH (genere par Deploy-AgentsGPO.ps1)"
  Write-Host "[+] GPO creee : $GpoName ($($Gpo.Id))"
} else {
  Write-Host "[=] GPO existante : $GpoName ($($Gpo.Id)) - mise a jour"
}

# --- 2. Tache planifiee GPP (ScheduledTasks.xml dans SYSVOL) ----------------------
$TaskDir = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\{$($Gpo.Id)}\Machine\Preferences\ScheduledTasks"
New-Item -ItemType Directory -Path $TaskDir -Force | Out-Null
$Cmd  = "powershell.exe"
$Args = "-NoProfile -ExecutionPolicy Bypass -File `"$Share\$DeployScript`""
$Uid  = "{$([guid]::NewGuid().ToString().ToUpper())}"
$Now  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$Boundary = (Get-Date -Format "yyyy-MM-dd") + "T12:00:00"

@"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="OMNI-SIEM-Deploy" image="0" changed="$Now" uid="$Uid" removePolicy="1" desc="Deploiement/MAJ Sysmon + Winlogbeat (SIEM OMNITECH)">
    <Properties action="R" name="OMNI-SIEM-Deploy" runAs="NT AUTHORITY\System" logonType="S4U">
      <Task version="1.2">
        <RegistrationInfo>
          <Author>OMNITECH Security</Author>
          <Description>Installe/met a jour Sysmon et Winlogbeat depuis NETLOGON\SIEM (idempotent). Log : C:\ProgramData\OMNI-SIEM\deploy.log</Description>
        </RegistrationInfo>
        <Principals>
          <Principal id="Author">
            <UserId>NT AUTHORITY\System</UserId>
            <RunLevel>HighestAvailable</RunLevel>
            <LogonType>S4U</LogonType>
          </Principal>
        </Principals>
        <Settings>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
          <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
          <StartWhenAvailable>true</StartWhenAvailable>
          <Enabled>true</Enabled>
          <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <IdleSettings><Duration>PT5M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
        </Settings>
        <Triggers>
          <BootTrigger>
            <Enabled>true</Enabled>
            <Delay>PT5M</Delay>
          </BootTrigger>
          <CalendarTrigger>
            <StartBoundary>$Boundary</StartBoundary>
            <Enabled>true</Enabled>
            <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
            <RandomDelay>PT2H</RandomDelay>
          </CalendarTrigger>
        </Triggers>
        <Actions Context="Author">
          <Exec>
            <Command>$Cmd</Command>
            <Arguments>$Args</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </TaskV2>
</ScheduledTasks>
"@ | Set-Content -Path (Join-Path $TaskDir "ScheduledTasks.xml") -Encoding UTF8
Write-Host "[+] ScheduledTasks.xml ecrit ($TaskDir)"

# --- 3. Enregistrer la CSE "Preferences/Scheduled Tasks" sur l'objet GPO ----------
#     {AADCED64...} = CSE Scheduled Tasks, {CAB54552...} = tool extension associee.
$CsePair = "[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
$GpoDn  = "CN={$($Gpo.Id)},CN=Policies,CN=System,$($Domain.DistinguishedName)"
$GpoObj = Get-ADObject -Identity $GpoDn -Properties gPCMachineExtensionNames
$Ext = $GpoObj.gPCMachineExtensionNames
if ([string]::IsNullOrEmpty($Ext)) { $Ext = "" }
if ($Ext -notlike "*AADCED64-746C-4633-A97C-D61349046527*") {
  $Blocks = @()
  if ($Ext) { $Blocks = [regex]::Matches($Ext, "\[[^\]]+\]") | ForEach-Object { $_.Value } }
  $Blocks += $CsePair
  $Sorted = $Blocks | Sort-Object { ($_ -replace "[\[\]]","").Substring(0,38) } -Unique
  Set-ADObject -Identity $GpoDn -Replace @{ gPCMachineExtensionNames = ($Sorted -join "") }
  Write-Host "[+] CSE Scheduled Tasks enregistree (gPCMachineExtensionNames)"
} else {
  Write-Host "[=] CSE Scheduled Tasks deja enregistree"
}

# --- 4. Bump de version GPO (sinon les clients n'appliquent pas le XML) -----------
#     Set-GPRegistryValue incremente la version machine ET pose un marqueur date.
Set-GPRegistryValue -Name $GpoName -Key "HKLM\SOFTWARE\OMNITECH\SIEM" `
  -ValueName "AgentsGpoStamp" -Type String -Value (Get-Date -Format "s") | Out-Null
Write-Host "[+] Version GPO incrementee (marqueur HKLM\SOFTWARE\OMNITECH\SIEM\AgentsGpoStamp)"

# --- 5. Liaison aux OU -------------------------------------------------------------
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
Write-Host "Termine. Sur un client : gpupdate /force, attendre le declencheur"
Write-Host "(demarrage +5 min ou 12h00 +0-2h), puis verifier :"
Write-Host "  Get-ScheduledTask OMNI-SIEM-Deploy ; Get-Service Sysmon64, winlogbeat"
Write-Host "Suivi global : dashboard Graylog 'OMNI - Windows Securite' (nouveaux hosts)"
