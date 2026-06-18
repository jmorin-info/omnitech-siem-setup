<#
.SYNOPSIS
  Install-OmniSiem-NinjaOne.ps1 - Enrolement SIEM OMNITECH complet, idempotent.
  REMPLACE Deploy-SiemAgents-NinjaOne.ps1 + Set-OmniAudit-NinjaOne.ps1.

.DESCRIPTION
  A lancer sur N'IMPORTE QUELLE machine Windows (avec ou sans installation
  prealable) : le script converge vers l'etat cible et VERIFIE tout.
  Tout est telecharge depuis le SIEM (https://<siem>/kit/), sans AD ni Internet.

    0. Root CA OMNITECH dans le magasin machine (TOFU au premier contact)
    1. Politique d'audit locale : baseline auditpol (audit-baseline.csv du kit),
       ligne de commande dans les 4688, ScriptBlockLogging 4104, politique
       avancee forcee, journal Security 2 Go circulaire
    2. Sysmon installe, config appliquee seulement si elle a change (hash)
    3. Winlogbeat OSS installe (version cible), conf /kit appliquee seulement
       si differente -> PAS de restart inutile en politique quotidienne.
       Si un serveur Veeam B&R est detecte (journal "Veeam Backup"), le canal
       est ajoute automatiquement a la conf de CETTE machine.
    4. Sante finale : services Running, test config + test output (5044),
       scan des logs winlogbeat pour les erreurs de canal ("requete invalide",
       cf. incident event_id trop longs) -> remontees en KO.

  Sortie NinjaOne : resume [OK]/[KO] par composant, exit 0 si tout OK, 1 sinon.
  Journal local : C:\ProgramData\OMNI-SIEM\install.log

.NOTES
  NinjaOne : Administration > Scripting > PowerShell, executer en SYSTEM,
  64 bits. Planification quotidienne recommandee (convergence + auto-reparation).
  Compatible Windows PowerShell 5.1 (aucun module requis).
#>
[CmdletBinding()]
param(
  [string]$BaseUrl           = "https://bx-it-graylog-vm.omnitech.security/kit",
  [string]$WinlogbeatVersion = "8.17.4",
  [string]$InstallDir        = "C:\Program Files\Winlogbeat",
  [int]   $SecurityLogMB     = 2048,
  [switch]$SkipAudit
)
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Staging = "C:\ProgramData\OMNI-SIEM"
New-Item -ItemType Directory -Path $Staging -Force | Out-Null
Start-Transcript -Path (Join-Path $Staging "install.log") -Append | Out-Null

$Report = [ordered]@{}   # composant -> "OK ..." / "KO ..."
function Step($m){ Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }
function Get-KitFile($Name, $Dest){
  Invoke-WebRequest -Uri "$BaseUrl/$Name" -OutFile $Dest -UseBasicParsing
  if (-not (Test-Path $Dest) -or (Get-Item $Dest).Length -eq 0) { throw "Telechargement vide : $Name" }
}
function Get-HashOrEmpty($Path){
  if (Test-Path $Path) { (Get-FileHash -Path $Path -Algorithm SHA256).Hash } else { "" }
}

# ============================ 0. ROOT CA ======================================
try {
  $CaSubject = "CN=Root CA OMNITECH SECURITY*"
  if (-not (Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like $CaSubject })) {
    Step "Root CA absente -> recuperation TOFU puis installation"
    $OldCb = [Net.ServicePointManager]::ServerCertificateValidationCallback
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try { Get-KitFile "omnitech-rootca.pem" (Join-Path $Staging "omnitech-rootca.pem") }
    finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $OldCb }
    Import-Certificate -FilePath (Join-Path $Staging "omnitech-rootca.pem") `
      -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
  }
  $Report["RootCA"] = "OK presente dans LocalMachine\Root"
} catch { $Report["RootCA"] = "KO $($_.Exception.Message)" }

# ============================ 1. AUDIT ========================================
if ($SkipAudit) { $Report["Audit"] = "OK ignore (-SkipAudit)" }
else {
  try {
    $AuditCsv = Join-Path $Staging "audit-baseline.csv"
    Get-KitFile "audit-baseline.csv" $AuditCsv
    Step "Application de la baseline d'audit (auditpol /restore)"
    $r = & auditpol.exe /restore /file:"$AuditCsv" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol /restore KO : $r" }

    function Set-Reg($Key,$Name,$Type,$Value){
      if (-not (Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
      New-ItemProperty -Path $Key -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    }
    Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" DWord 1
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" DWord 1
    Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" DWord 1

    & wevtutil.exe sl Security /ms:$($SecurityLogMB * 1MB) /rt:false /ab:false 2>&1 | Out-Null
    # OS FR ou EN : auditpol affiche "Reussite"/"Success" selon la locale
    $active = (& auditpol.exe /get /category:* | Select-String "Success|ussite").Count
    if ($active -lt 20) { throw "seulement $active sous-categories auditees apres restore" }
    $Report["Audit"] = "OK $active sous-categories actives, Security ${SecurityLogMB}Mo"
  } catch { $Report["Audit"] = "KO $($_.Exception.Message)" }
}

# ============================ 2. SYSMON =======================================
try {
  $SysExe = Join-Path $Staging "Sysmon64.exe"
  $SysCfg = Join-Path $Staging "sysmonconfig-omnitech.xml"
  $SysCfgNew = Join-Path $Staging "sysmonconfig-omnitech.new.xml"
  Get-KitFile "sysmonconfig-omnitech.xml" $SysCfgNew
  $Svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
  if (-not $Svc) {
    Step "Installation de Sysmon"
    Get-KitFile "Sysmon64.exe" $SysExe
    Move-Item $SysCfgNew $SysCfg -Force
    & $SysExe -accepteula -i $SysCfg | Out-Null
  } elseif ((Get-HashOrEmpty $SysCfgNew) -ne (Get-HashOrEmpty $SysCfg)) {
    Step "Sysmon present -> configuration modifiee, mise a jour"
    if (-not (Test-Path $SysExe)) { Get-KitFile "Sysmon64.exe" $SysExe }
    Move-Item $SysCfgNew $SysCfg -Force
    & $SysExe -c $SysCfg | Out-Null
  } else {
    Remove-Item $SysCfgNew -Force
    Step "Sysmon present, configuration inchangee"
  }
  if ((Get-Service Sysmon64).Status -ne "Running") { Start-Service Sysmon64 }
  $Report["Sysmon"] = "OK service $((Get-Service Sysmon64).Status)"
} catch { $Report["Sysmon"] = "KO $($_.Exception.Message)" }

# ============================ 3. WINLOGBEAT ===================================
try {
  $NeedRestart = $false

  # --- binaire (version cible) ---
  $VersionFile = Join-Path $InstallDir "version.txt"
  $Installed = if (Test-Path $VersionFile) { Get-Content $VersionFile } else { "" }
  if ($Installed -ne $WinlogbeatVersion) {
    Step "Deploiement Winlogbeat OSS $WinlogbeatVersion (present: '$Installed')"
    $ZipName = "winlogbeat-oss-$WinlogbeatVersion-windows-x86_64.zip"
    $Zip = Join-Path $Staging $ZipName
    Get-KitFile $ZipName $Zip
    if (Get-Service winlogbeat -ErrorAction SilentlyContinue) {
      Stop-Service winlogbeat -Force -ErrorAction SilentlyContinue
    }
    $Tmp = Join-Path $Staging "wlb-extract"
    Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -Path $Zip -DestinationPath $Tmp -Force
    $Inner = Get-ChildItem $Tmp -Directory | Select-Object -First 1
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item (Join-Path $Inner.FullName "*") $InstallDir -Recurse -Force
    Set-Content -Path $VersionFile -Value $WinlogbeatVersion
    Remove-Item $Zip, $Tmp -Recurse -Force -ErrorAction SilentlyContinue
    $NeedRestart = $true
  }

  # --- configuration : /kit + canal Veeam si serveur Veeam B&R detecte -------
  $YmlNew = Join-Path $Staging "winlogbeat.new.yml"
  Get-KitFile "winlogbeat.yml" $YmlNew
  if (Get-WinEvent -ListLog "Veeam Backup" -ErrorAction SilentlyContinue) {
    Step "Journal 'Veeam Backup' detecte -> ajout du canal a la conf locale"
    $VeeamBlock = "`n`n  # --- Veeam Backup & Replication (serveur Veeam detecte ici) --------------`n  - name: Veeam Backup`n    ignore_older: 72h"
    (Get-Content $YmlNew -Raw) -replace "(?m)^winlogbeat\.event_logs:", ("winlogbeat.event_logs:" + $VeeamBlock) |
      Set-Content -Path $YmlNew -Encoding UTF8
  }
  $YmlCur = Join-Path $InstallDir "winlogbeat.yml"
  if ((Get-HashOrEmpty $YmlNew) -ne (Get-HashOrEmpty $YmlCur)) {
    Step "Configuration winlogbeat differente -> application"
    Copy-Item $YmlNew $YmlCur -Force
    $NeedRestart = $true
  } else { Step "Configuration winlogbeat inchangee" }
  Remove-Item $YmlNew -Force -ErrorAction SilentlyContinue

  # --- CA pour Beats ---
  $CaNew = Join-Path $Staging "rootca.new.pem"
  Get-KitFile "omnitech-rootca.pem" $CaNew
  $CaCur = Join-Path $InstallDir "omnitech-rootca.pem"
  if ((Get-HashOrEmpty $CaNew) -ne (Get-HashOrEmpty $CaCur)) {
    Copy-Item $CaNew $CaCur -Force; $NeedRestart = $true
  }
  Remove-Item $CaNew -Force -ErrorAction SilentlyContinue

  # --- service ---
  if (-not (Get-Service winlogbeat -ErrorAction SilentlyContinue)) {
    Step "Creation du service winlogbeat"
    $BinPath = ('"{0}\winlogbeat.exe" --environment=windows_service ' +
                '-c "{0}\winlogbeat.yml" ' +
                '--path.home "{0}" --path.data "C:\ProgramData\winlogbeat" ' +
                '--path.logs "C:\ProgramData\winlogbeat\logs" -E logging.files.redirect_stderr=true') -f $InstallDir
    New-Service -Name winlogbeat -DisplayName "Winlogbeat (OMNITECH SIEM)" `
      -BinaryPathName $BinPath -StartupType Automatic | Out-Null
    $NeedRestart = $true
  }
  sc.exe failure winlogbeat reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

  # --- validation AVANT (re)demarrage ---
  $Test = & (Join-Path $InstallDir "winlogbeat.exe") test config `
            -c $YmlCur --path.home $InstallDir 2>&1
  if ($LASTEXITCODE -ne 0) { throw "winlogbeat test config KO : $Test" }

  $SvcState = (Get-Service winlogbeat).Status
  if ($SvcState -ne "Running") { Start-Service winlogbeat; Step "Service demarre" }
  elseif ($NeedRestart)        { Restart-Service winlogbeat; Step "Service redemarre (changements appliques)" }
  else                         { Step "Service deja Running, rien a redemarrer" }
  $Report["Winlogbeat"] = "OK $WinlogbeatVersion, service $((Get-Service winlogbeat).Status)"
} catch { $Report["Winlogbeat"] = "KO $($_.Exception.Message)" }

# ============================ 4. SANTE ========================================
try {
  $Out = & (Join-Path $InstallDir "winlogbeat.exe") test output `
           -c (Join-Path $InstallDir "winlogbeat.yml") --path.home $InstallDir 2>&1
  $OutTxt = ($Out | Out-String)
  if ($OutTxt -match "talk to server\.+\s*OK") { $Report["Sortie 5044"] = "OK connexion + TLS vers le SIEM" }
  else {
    $Err = ($Out | Select-String "error|ERROR" | Select-Object -First 1)
    throw "test output : $Err"
  }
} catch { $Report["Sortie 5044"] = "KO $($_.Exception.Message)" }

try {
  Start-Sleep -Seconds 8   # laisser winlogbeat ouvrir les canaux
  $LogDirs = @("C:\ProgramData\winlogbeat\logs", "C:\ProgramData\winlogbeat\Logs")
  $LogFile = $LogDirs | ForEach-Object { Get-ChildItem $_ -Filter "winlogbeat*" -ErrorAction SilentlyContinue } |
             Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $LogFile) { throw "aucun fichier de log winlogbeat trouve" }
  $Since = (Get-Date).AddMinutes(-3)
  $BadLines = Get-Content $LogFile.FullName -Tail 300 | Where-Object {
    $_ -match '"log\.level":"error"' -and
    ($_ -notmatch '"@timestamp":"(?<ts>[^"]+)"' -or ([datetime]::Parse($Matches.ts) -gt $Since))
  }
  $ChannelErr = $BadLines | Where-Object { $_ -match "invalide|invalid query|Open\(\) error" } | Select-Object -First 1
  if ($ChannelErr) { throw ("erreur d'ouverture de canal : " + $ChannelErr.Substring(0, [Math]::Min(180, $ChannelErr.Length))) }
  if ($BadLines.Count -gt 0) {
    $Report["Canaux"] = "KO $($BadLines.Count) erreur(s) recente(s) dans les logs winlogbeat"
  } else {
    $NbCanaux = (Select-String -Path (Join-Path $InstallDir "winlogbeat.yml") -Pattern "^\s*- name:").Count
    $Report["Canaux"] = "OK $NbCanaux canaux configures, aucune erreur de lecture"
  }
} catch { $Report["Canaux"] = "KO $($_.Exception.Message)" }

# ===================== INVENTAIRE (vulnerabilites) ===========================
# Collecteur logiciel + OS/correctifs pour la detection de vulnerabilites
# (KEV + anciennete patch, cote SIEM). Tache quotidienne SYSTEM ; alimente le
# canal OMNI-Inventaire (deja present dans le winlogbeat.yml applique ci-dessus).
try {
  $InvDir = "C:\ProgramData\OMNI-SIEM"
  New-Item -ItemType Directory -Path $InvDir -Force | Out-Null
  $InvPs = Join-Path $InvDir "Get-OmniInventory.ps1"
  Get-KitFile "Get-OmniInventory.ps1" $InvPs
  $actInv = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$InvPs`""
  $trgInv = New-ScheduledTaskTrigger -Daily -At 2:00am
  $prnInv = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName "OMNI-Inventory" -Action $actInv -Trigger $trgInv `
    -Principal $prnInv -Description "Inventaire logiciel/OS -> SIEM (vulnerabilites)" -Force | Out-Null
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InvPs *> $null   # 1er inventaire immediat
  $Report["Inventaire"] = "OK tache quotidienne OMNI-Inventory + 1er inventaire emis"
} catch { $Report["Inventaire"] = "KO $($_.Exception.Message)" }

# ============================ RESUME ==========================================
Write-Host ""
Write-Host "================ RESUME OMNI-SIEM ($env:COMPUTERNAME) ================"
$Fail = $false
foreach ($k in $Report.Keys) {
  $v = $Report[$k]
  Write-Host ("  {0,-12} : {1}" -f $k, $v)
  if ($v -like "KO*") { $Fail = $true }
}
Write-Host "======================================================================"
Stop-Transcript | Out-Null
if ($Fail) { exit 1 } else { exit 0 }
