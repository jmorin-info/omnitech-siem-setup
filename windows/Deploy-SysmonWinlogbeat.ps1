<#
.SYNOPSIS
  Deploy-SysmonWinlogbeat.ps1 - Deploiement/MAJ Sysmon + Winlogbeat OSS
  via NinjaOne (ou GPO startup script). Idempotent, sans Internet sur le poste.

.DESCRIPTION
  Source de distribution : \\omnitech.security\NETLOGON\SIEM  (replique sur
  les 2 DC, lisible par les comptes ordinateurs - y deposer une seule fois) :
    - Sysmon64.exe                       (https://live.sysinternals.com)
    - sysmonconfig-omnitech.xml          (fourni dans ce kit)
    - winlogbeat-oss-<ver>-windows-x86_64.zip  (artifacts.elastic.co - version
      OSS OBLIGATOIRE : la distribution standard refuse les sorties non-Elastic)
    - winlogbeat.yml                     (fourni dans ce kit)
    - omnitech-rootca.pem                (Root CA OMNITECH SECURITY en base64)

  Le script :
    1. installe ou met a jour Sysmon (-i / -c selon presence du service)
    2. installe ou met a jour Winlogbeat dans C:\Program Files\Winlogbeat,
       depose yml + CA, cree/repare le service, configure le redemarrage auto
    3. valide la conf (winlogbeat test config) avant de demarrer
  Codes retour NinjaOne : 0 = OK, 1 = echec (details dans le log + transcript).

.NOTES
  Log : C:\ProgramData\OMNI-SIEM\deploy.log
#>
[CmdletBinding()]
param(
  [string]$Share             = "\\omnitech.security\NETLOGON\SIEM",
  [string]$WinlogbeatVersion = "8.17.4",   # adapter au zip depose dans le partage
  [string]$InstallDir        = "C:\Program Files\Winlogbeat"
)
$ErrorActionPreference = "Stop"
$Staging = "C:\ProgramData\OMNI-SIEM"
New-Item -ItemType Directory -Path $Staging -Force | Out-Null
Start-Transcript -Path (Join-Path $Staging "deploy.log") -Append | Out-Null
$Fail = $false

function Step($m){ Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }

try {
  if (-not (Test-Path $Share)) { throw "Partage inaccessible : $Share" }

  # ============================ 1. SYSMON =====================================
  $SysmonExe = Join-Path $Share "Sysmon64.exe"
  $SysmonCfg = Join-Path $Share "sysmonconfig-omnitech.xml"
  if ((Test-Path $SysmonExe) -and (Test-Path $SysmonCfg)) {
    Copy-Item $SysmonExe,$SysmonCfg -Destination $Staging -Force
    $LocalExe = Join-Path $Staging "Sysmon64.exe"
    $LocalCfg = Join-Path $Staging "sysmonconfig-omnitech.xml"
    if (Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue) {
      Step "Sysmon present -> mise a jour de la configuration"
      & $LocalExe -c $LocalCfg | Out-Null
    } else {
      Step "Installation de Sysmon"
      & $LocalExe -accepteula -i $LocalCfg | Out-Null
    }
    if ((Get-Service Sysmon64).Status -ne "Running") { Start-Service Sysmon64 }
    Step "Sysmon OK ($((Get-Service Sysmon64).Status))"
  } else {
    Step "ATTENTION: Sysmon64.exe/config absents du partage -> etape sautee"
    $Fail = $true
  }

  # ============================ 2. WINLOGBEAT =================================
  $Zip = Join-Path $Share ("winlogbeat-oss-{0}-windows-x86_64.zip" -f $WinlogbeatVersion)
  $Yml = Join-Path $Share "winlogbeat.yml"
  $Ca  = Join-Path $Share "omnitech-rootca.pem"
  foreach ($f in @($Zip,$Yml,$Ca)) { if (-not (Test-Path $f)) { throw "Fichier manquant sur le partage : $f" } }

  $VersionFile = Join-Path $InstallDir "version.txt"
  $Installed   = if (Test-Path $VersionFile) { Get-Content $VersionFile } else { "" }

  if ($Installed -ne $WinlogbeatVersion) {
    Step "Deploiement Winlogbeat OSS $WinlogbeatVersion (present: '$Installed')"
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
  } else {
    Step "Winlogbeat $WinlogbeatVersion deja en place"
  }

  # Conf + CA (toujours rafraichies : permet de pousser un changement de conf)
  Copy-Item $Yml (Join-Path $InstallDir "winlogbeat.yml") -Force
  Copy-Item $Ca  (Join-Path $InstallDir "omnitech-rootca.pem") -Force

  # Service
  if (-not (Get-Service winlogbeat -ErrorAction SilentlyContinue)) {
    Step "Creation du service winlogbeat"
    $BinPath = ('"{0}\winlogbeat.exe" --environment=windows_service ' +
                '-c "{0}\winlogbeat.yml" ' +
                '--path.home "{0}" --path.data "C:\ProgramData\winlogbeat" ' +
                '--path.logs "C:\ProgramData\winlogbeat\logs" -E logging.files.redirect_stderr=true') -f $InstallDir
    New-Service -Name winlogbeat -DisplayName "Winlogbeat (OMNITECH SIEM)" `
      -BinaryPathName $BinPath -StartupType Automatic | Out-Null
  }
  sc.exe failure winlogbeat reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

  # Validation de la conf AVANT demarrage (erreur YAML = service en boucle sinon)
  Step "Validation de la configuration"
  $Test = & (Join-Path $InstallDir "winlogbeat.exe") test config `
            -c (Join-Path $InstallDir "winlogbeat.yml") --path.home $InstallDir 2>&1
  if ($LASTEXITCODE -ne 0) { throw "winlogbeat test config KO : $Test" }

  Start-Service winlogbeat
  Step "Winlogbeat OK ($((Get-Service winlogbeat).Status))"

  # Test de sortie vers Graylog (non bloquant : flux 5044 peut-etre pas encore ouvert)
  $Out = & (Join-Path $InstallDir "winlogbeat.exe") test output `
           -c (Join-Path $InstallDir "winlogbeat.yml") --path.home $InstallDir 2>&1
  Step ("Test sortie 5044 : " + (($Out | Select-String "talk to server|error" | Select-Object -First 1) -replace "`r?`n"," "))
}
catch {
  Step ("ERREUR : " + $_.Exception.Message)
  $Fail = $true
}
finally {
  Stop-Transcript | Out-Null
}
if ($Fail) { exit 1 } else { exit 0 }
