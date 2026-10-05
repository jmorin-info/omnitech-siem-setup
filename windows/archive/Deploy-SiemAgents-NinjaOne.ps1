<#
.SYNOPSIS
  Deploy-SiemAgents-NinjaOne.ps1 - Installation/MAJ Sysmon + Winlogbeat
  AUTONOME : telecharge tout depuis le SIEM (https://<siem>/kit/), sans AD,
  sans NETLOGON, sans Internet sur le poste. Concu pour NinjaOne.

.DESCRIPTION
  Le SIEM heberge le kit sur https://bx-it-graylog-vm.omnitech.security/kit/ :
    Sysmon64.exe, sysmonconfig-omnitech.xml,
    winlogbeat-oss-<ver>-windows-x86_64.zip, winlogbeat.yml, omnitech-rootca.pem
  Le script :
    0. installe la Root CA OMNITECH dans le magasin machine si absente
       (1er fetch de la CA en mode "trust on first use", tout le reste est
       verifie TLS normalement ; les machines du domaine ont deja la CA via GPO)
    1. installe / met a jour Sysmon (-i / -c selon presence du service)
    2. installe / met a jour Winlogbeat OSS + conf + CA, service auto-restart
    3. valide la conf (winlogbeat test config) avant demarrage
  Idempotent : peut tourner tous les jours (politique NinjaOne), il converge.

.NOTES
  NinjaOne : Administration > Scripting > PowerShell, executer en SYSTEM, 64 bits.
  Codes retour : 0 = OK, 1 = echec (details : C:\ProgramData\OMNI-SIEM\deploy.log)
#>
[CmdletBinding()]
param(
  [string]$BaseUrl           = "https://bx-it-graylog-vm.omnitech.security/kit",
  [string]$WinlogbeatVersion = "8.17.4",
  [string]$InstallDir        = "C:\Program Files\Winlogbeat"
)
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Staging = "C:\ProgramData\OMNI-SIEM"
New-Item -ItemType Directory -Path $Staging -Force | Out-Null
Start-Transcript -Path (Join-Path $Staging "deploy.log") -Append | Out-Null
$Fail = $false

function Step($m){ Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }
function Get-KitFile($Name, $Dest){
  Invoke-WebRequest -Uri "$BaseUrl/$Name" -OutFile $Dest -UseBasicParsing
  if (-not (Test-Path $Dest) -or (Get-Item $Dest).Length -eq 0) { throw "Telechargement vide : $Name" }
}

try {
  # ===================== 0. ROOT CA (magasin machine) ========================
  $CaSubject = "CN=Root CA OMNITECH SECURITY*"
  $HasCa = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like $CaSubject }
  if (-not $HasCa) {
    Step "Root CA absente -> recuperation depuis le SIEM (TOFU) puis installation"
    $OldCb = [Net.ServicePointManager]::ServerCertificateValidationCallback
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try { Get-KitFile "omnitech-rootca.pem" (Join-Path $Staging "omnitech-rootca.pem") }
    finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $OldCb }
    Import-Certificate -FilePath (Join-Path $Staging "omnitech-rootca.pem") `
      -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Step "Root CA OMNITECH installee dans LocalMachine\Root"
  }

  # ===================== 1. SYSMON ============================================
  $LocalExe = Join-Path $Staging "Sysmon64.exe"
  $LocalCfg = Join-Path $Staging "sysmonconfig-omnitech.xml"
  Get-KitFile "sysmonconfig-omnitech.xml" $LocalCfg
  if (Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue) {
    Step "Sysmon present -> mise a jour de la configuration"
    if (-not (Test-Path $LocalExe)) { Get-KitFile "Sysmon64.exe" $LocalExe }
    & $LocalExe -c $LocalCfg | Out-Null
  } else {
    Step "Installation de Sysmon"
    Get-KitFile "Sysmon64.exe" $LocalExe
    & $LocalExe -accepteula -i $LocalCfg | Out-Null
  }
  if ((Get-Service Sysmon64).Status -ne "Running") { Start-Service Sysmon64 }
  Step "Sysmon OK ($((Get-Service Sysmon64).Status))"

  # ===================== 2. WINLOGBEAT ========================================
  $VersionFile = Join-Path $InstallDir "version.txt"
  $Installed   = if (Test-Path $VersionFile) { Get-Content $VersionFile } else { "" }

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
  } else {
    Step "Winlogbeat $WinlogbeatVersion deja en place"
  }

  # Conf + CA : toujours rafraichies (pousser une nouvelle conf = MAJ /kit cote SIEM)
  Get-KitFile "winlogbeat.yml"      (Join-Path $InstallDir "winlogbeat.yml")
  Get-KitFile "omnitech-rootca.pem" (Join-Path $InstallDir "omnitech-rootca.pem")

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

  Step "Validation de la configuration"
  $Test = & (Join-Path $InstallDir "winlogbeat.exe") test config `
            -c (Join-Path $InstallDir "winlogbeat.yml") --path.home $InstallDir 2>&1
  if ($LASTEXITCODE -ne 0) { throw "winlogbeat test config KO : $Test" }

  if ((Get-Service winlogbeat).Status -ne "Running") { Start-Service winlogbeat } else { Restart-Service winlogbeat }
  Step "Winlogbeat OK ($((Get-Service winlogbeat).Status))"

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
