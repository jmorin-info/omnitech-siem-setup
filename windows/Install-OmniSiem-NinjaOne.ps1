<#
.SYNOPSIS
  Install-OmniSiem-NinjaOne.ps1 - Enrolement SIEM Windows complet, idempotent.

.DESCRIPTION
  A lancer sur n'importe quelle machine Windows (avec ou sans installation
  prealable) : le script converge vers l'etat cible et verifie tout.
  Tout est telecharge depuis le SIEM du site (https://<siem>/kit/), sans AD ni
  Internet, et chaque fichier est controle par SHA256SUMS avant usage.

    0. Manifeste SHA256SUMS du kit (HTTPS valide obligatoire). Certificat de
       collecte installe dans le magasin machine seulement si le site l'a
       demande (KIT_INSTALL_ROOT_CA=1 dans 00-vars.env), compare par empreinte.
    1. Politique d'audit locale (postes et serveurs membres ; jamais sur un DC,
       ou la GPO fait foi) : baseline auditpol, ligne de commande des 4688,
       ScriptBlockLogging 4104, politique avancee forcee. Le journal Security
       est agrandi jusqu'a la taille cible, jamais reduit.
    2. Sysmon (signature Microsoft verifiee), configuration appliquee
       seulement si elle a change.
    3. Winlogbeat (signature Elastic verifiee) : jamais de retour a une version
       plus ancienne ; nouvelle configuration validee AVANT d'etre posee, ancienne
       configuration conservee (.precedent) ; redemarrage seulement si quelque
       chose a change.
    4. Sante : service demarre, connexion TCP etablie vers le SIEM:5044. Le
       " winlogbeat test output " n'est lance qu'en diagnostic (aucune connexion
       etablie) : lance a chaque passage, il ferme sa connexion de test par un RST
       et fait apparaitre des coupures cote SIEM.
    5. Inventaire : tache quotidienne creee une seule fois (pas de -Force a
       chaque passage, pas de fuseau fige), premier inventaire seulement a la
       creation ou au changement du script.

  -Simulation : aucune modification du systeme. Le kit est telecharge et verifie
  dans -StagingDir, la configuration est validee par le binaire du kit
  (winlogbeat test config), et le rapport indique ce qui serait change.
  -KitPath (simulation seulement) : lit un kit local au lieu du SIEM.

  Sortie : resume [OK]/[KO] par composant, exit 0 si tout OK, 1 sinon.
  Journal local : C:\ProgramData\OMNI-SIEM\install.log

.NOTES
  NinjaOne : executer en SYSTEM, 64 bits. Planification quotidienne conseillee
  (convergence et auto-reparation) ; plus frequent est inutile.
  Compatible Windows PowerShell 5.1 et PowerShell 7, Windows en francais ou en
  anglais (aucun texte localise n'est interprete).
#>
[CmdletBinding()]
param(
  [string]$BaseUrl           = "https://__SIEM_FQDN__/kit",
  [string]$WinlogbeatVersion = "__WINLOGBEAT_VERSION__",
  [string]$InstallDir        = "C:\Program Files\Winlogbeat",
  [int]   $SecurityLogMB     = 2048,
  [switch]$SkipAudit,
  [switch]$Simulation,
  [string]$KitPath           = "",
  [string]$StagingDir        = ""
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

# --- Parametres du site (rendus par 95-kit-deploy.sh) ------------------------
$AllowedBaseUrl  = "https://__SIEM_FQDN__/kit"
$BeatsCaName     = "__BEATS_CA_FILE__"
$InstallRootCa   = ("__KIT_INSTALL_ROOT_CA__" -eq "1")
$BeatsPort       = 5044
$MinManifestSize = 8

# Etat installe (toujours ici) et repertoire de travail (telechargements).
$LiveDir = Join-Path $env:ProgramData "OMNI-SIEM"
if (-not $Simulation) { $StagingDir = $LiveDir }
elseif (-not $StagingDir) { $StagingDir = Join-Path $env:TEMP "OMNI-SIEM-simulation" }
$Staging = $StagingDir
if (-not $Simulation) { New-Item -ItemType Directory -Path $LiveDir -Force | Out-Null }
New-Item -ItemType Directory -Path $Staging -Force | Out-Null
$Transcript = $false
if (-not $Simulation) {
  try { Start-Transcript -Path (Join-Path $Staging "install.log") -Append | Out-Null; $Transcript = $true } catch { }
}

$Report = [ordered]@{}   # composant -> "OK ..." / "KO ..."
function Step([string]$m) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }
function Finish([int]$Code) {
  Write-Host ""
  $mode = ""
  if ($Simulation) { $mode = " - SIMULATION, rien n'a ete modifie" }
  Write-Host ("================ RESUME OMNI-SIEM ({0}){1} ================" -f $env:COMPUTERNAME, $mode)
  foreach ($k in $Report.Keys) {
    Write-Host ("  {0,-12} : {1}" -f $k, $Report[$k])
    if ([string]$Report[$k] -like "KO*") { $Code = 1 }
  }
  Write-Host "======================================================================"
  if ($Transcript) { try { Stop-Transcript | Out-Null } catch { } }
  exit $Code
}
function Get-HashOrEmpty([string]$Path) {
  if (Test-Path -LiteralPath $Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash } else { "" }
}

# Compte les sous-categories auditees a partir de " auditpol /backup ".
# Lecture par POSITION de colonne (les en-tetes et libelles sont traduits sur
# un Windows francais) : 2 = GUID de sous-categorie, 7 = valeur 0..3.
function ConvertFrom-OmniAuditBackup([string[]]$Lines) {
  $n = 0
  $rows = @($Lines | Select-Object -Skip 1 | ConvertFrom-Csv -Header c0, c1, c2, c3, c4, c5, c6)
  foreach ($row in $rows) {
    if ([string]$row.c3 -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { continue }
    if (([string]$row.c6).Trim() -match '^[123]$') { $n++ }
  }
  return $n
}

# Extrait la version d'une sortie " winlogbeat version ".
function Get-OmniBeatVersion([string]$Text) {
  if ($Text -match 'version\s+(\d+\.\d+\.\d+)') { return $Matches[1] }
  return ""
}

function Assert-Signature([string]$Path, [string]$Publisher) {
  $sig = Get-AuthenticodeSignature -FilePath $Path
  if ($sig.Status -ne "Valid" -or $null -eq $sig.SignerCertificate -or
      $sig.SignerCertificate.Subject -notmatch ('O="?' + [regex]::Escape($Publisher))) {
    throw ("Signature {0} invalide : {1} ({2})" -f $Publisher, $Path, $sig.Status)
  }
}

# ============================ 0. MANIFESTE ====================================
try {
  if ($KitPath) {
    if (-not $Simulation) { throw "-KitPath n'est accepte qu'avec -Simulation" }
    if (-not (Test-Path -LiteralPath (Join-Path $KitPath "SHA256SUMS"))) { throw "SHA256SUMS absent de $KitPath" }
  } else {
    if ($BaseUrl -ne $AllowedBaseUrl) { throw "URL du kit non autorisee : $BaseUrl (attendu $AllowedBaseUrl)" }
    if ($BaseUrl -notmatch '^https://[A-Za-z0-9.-]+(:\d+)?/kit$') { throw "URL du kit invalide : $BaseUrl" }
    if ($null -ne [Net.ServicePointManager]::ServerCertificateValidationCallback) {
      throw "Validation TLS personnalisee detectee dans la session : refus"
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  }
  $ManifestPath = Join-Path $Staging "SHA256SUMS"
  if ($KitPath) { Copy-Item -LiteralPath (Join-Path $KitPath "SHA256SUMS") -Destination $ManifestPath -Force }
  else { Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS" -OutFile $ManifestPath -UseBasicParsing -TimeoutSec 60 }
  $KitChecksums = @{}
  foreach ($line in (Get-Content -LiteralPath $ManifestPath)) {
    $line = $line.TrimStart([char]0xFEFF)
    if ($line -match '^([0-9a-fA-F]{64})\s+\*?(?:\./)?([A-Za-z0-9_.-]+)\s*$') {
      $KitChecksums[$Matches[2]] = $Matches[1].ToUpperInvariant()
    }
  }
  if ($KitChecksums.Count -lt $MinManifestSize) { throw "Manifeste SHA256SUMS incomplet ($($KitChecksums.Count) entrees)" }
  $Report["Kit"] = "OK manifeste SHA256 ($($KitChecksums.Count) fichiers)"
} catch {
  $Report["Kit"] = "KO $($_.Exception.Message)"
  Finish 1
}

function Get-KitFile([string]$Name, [string]$Dest) {
  if (-not $KitChecksums.ContainsKey($Name)) { throw "Empreinte SHA256 absente du manifeste : $Name" }
  $tmp = "$Dest.download"
  try {
    if ($KitPath) { Copy-Item -LiteralPath (Join-Path $KitPath $Name) -Destination $tmp -Force }
    else { Invoke-WebRequest -Uri "$BaseUrl/$Name" -OutFile $tmp -UseBasicParsing -TimeoutSec 600 }
    if (-not (Test-Path -LiteralPath $tmp) -or (Get-Item -LiteralPath $tmp).Length -eq 0) { throw "Telechargement vide : $Name" }
    if ((Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash -ne $KitChecksums[$Name]) { throw "Integrite SHA256 invalide : $Name" }
    Move-Item -LiteralPath $tmp -Destination $Dest -Force
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $Simulation -and -not $IsAdmin) {
  $Report["Droits"] = "KO administrateur ou SYSTEM requis"
  Finish 1
}
$DomainRole = 0
try { $DomainRole = [int](Get-CimInstance Win32_ComputerSystem).DomainRole } catch { }
$IsDC = ($DomainRole -ge 4)

# ============================ 0bis. CERTIFICAT ================================
try {
  $CaFile = Join-Path $Staging $BeatsCaName
  Get-KitFile $BeatsCaName $CaFile
  $Ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CaFile)
  if (-not $InstallRootCa) {
    $Report["Certificat"] = "OK $($Ca.Thumbprint) (fichier Winlogbeat seulement)"
  } elseif (Test-Path -LiteralPath ("Cert:\LocalMachine\Root\" + $Ca.Thumbprint)) {
    $Report["Certificat"] = "OK $($Ca.Thumbprint) deja dans LocalMachine\Root"
  } elseif ($Simulation) {
    $Report["Certificat"] = "OK serait ajoute a LocalMachine\Root : $($Ca.Subject)"
  } else {
    Step "Certificat absent du magasin machine -> ajout ($($Ca.Subject))"
    Import-Certificate -FilePath $CaFile -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    $Report["Certificat"] = "OK $($Ca.Thumbprint) ajoute a LocalMachine\Root"
  }
} catch { $Report["Certificat"] = "KO $($_.Exception.Message)" }

# ============================ 1. AUDIT ========================================
if ($SkipAudit) { $Report["Audit"] = "OK ignore (-SkipAudit)" }
elseif ($IsDC) { $Report["Audit"] = "OK controleur de domaine : audit gere par GPO, non modifie" }
elseif (-not $IsAdmin) { $Report["Audit"] = "OK non controle (simulation sans droits administrateur)" }
else {
  try {
    $AuditCsv = Join-Path $Staging "audit-baseline.csv"
    Get-KitFile "audit-baseline.csv" $AuditCsv
    $SecLog = Get-WinEvent -ListLog Security
    $TargetBytes = [int64]$SecurityLogMB * 1MB
    if ($Simulation) {
      $bk = Join-Path $Staging "auditpol-actuel.csv"
      & auditpol.exe /backup /file:"$bk" | Out-Null
      $active = ConvertFrom-OmniAuditBackup (Get-Content -LiteralPath $bk)
      Remove-Item -LiteralPath $bk -Force -ErrorAction SilentlyContinue
      $grow = ""
      if ($SecLog.MaximumSizeInBytes -lt $TargetBytes) { $grow = ", journal Security serait porte a ${SecurityLogMB} Mo" }
      $Report["Audit"] = "OK $active sous-categories actives aujourd'hui ; baseline verifiee, serait appliquee$grow"
    } else {
      Step "Application de la baseline d'audit (auditpol /restore)"
      $r = & auditpol.exe /restore /file:"$AuditCsv" 2>&1
      if ($LASTEXITCODE -ne 0) { throw "auditpol /restore KO : $r" }
      function Set-Reg($Key, $Name, $Type, $Value) {
        if (-not (Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
        New-ItemProperty -Path $Key -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
      }
      Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" DWord 1
      Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" DWord 1
      Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" DWord 1
      # Agrandir seulement : une GPO ou un administrateur a pu fixer plus grand.
      if ($SecLog.MaximumSizeInBytes -lt $TargetBytes) {
        & wevtutil.exe sl Security /ms:$TargetBytes 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "wevtutil sl Security KO ($LASTEXITCODE)" }
      }
      $bk = Join-Path $Staging "auditpol-controle.csv"
      & auditpol.exe /backup /file:"$bk" | Out-Null
      $active = ConvertFrom-OmniAuditBackup (Get-Content -LiteralPath $bk)
      Remove-Item -LiteralPath $bk -Force -ErrorAction SilentlyContinue
      if ($active -lt 20) { throw "seulement $active sous-categories auditees apres restore" }
      $size = [math]::Round(((Get-WinEvent -ListLog Security).MaximumSizeInBytes / 1MB), 0)
      $Report["Audit"] = "OK $active sous-categories actives, journal Security $size Mo"
    }
  } catch { $Report["Audit"] = "KO $($_.Exception.Message)" }
}

# ============================ 2. SYSMON =======================================
try {
  $SysExe = Join-Path $Staging "Sysmon64.exe"
  $SysCfg = Join-Path $LiveDir "sysmonconfig-omnitech.xml"
  $SysCfgNew = Join-Path $Staging "sysmonconfig-omnitech.new.xml"
  Get-KitFile "sysmonconfig-omnitech.xml" $SysCfgNew
  $Svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
  $CfgChanged = ((Get-HashOrEmpty $SysCfgNew) -ne (Get-HashOrEmpty $SysCfg))
  if ((-not $Svc) -or $CfgChanged -or $Simulation) {
    if ($KitChecksums.ContainsKey("Sysmon64.exe")) {
      if (-not (Test-Path -LiteralPath $SysExe) -or (Get-HashOrEmpty $SysExe) -ne $KitChecksums["Sysmon64.exe"]) {
        Get-KitFile "Sysmon64.exe" $SysExe
      }
      Assert-Signature $SysExe "Microsoft Corporation"
    } elseif (-not $Svc) { throw "Sysmon64.exe absent du kit" }
  }
  if ($Simulation) {
    Remove-Item -LiteralPath $SysCfgNew -Force -ErrorAction SilentlyContinue
    if (-not $Svc) { $Report["Sysmon"] = "OK serait installe (binaire signe Microsoft verifie)" }
    elseif ($CfgChanged) { $Report["Sysmon"] = "OK configuration serait mise a jour" }
    else { $Report["Sysmon"] = "OK present, configuration inchangee" }
  } else {
    if (-not $Svc) {
      Step "Installation de Sysmon"
      Move-Item -LiteralPath $SysCfgNew -Destination $SysCfg -Force
      & $SysExe -accepteula -i $SysCfg | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Sysmon -i KO ($LASTEXITCODE)" }
    } elseif ($CfgChanged) {
      Step "Sysmon present -> configuration modifiee, mise a jour"
      Move-Item -LiteralPath $SysCfgNew -Destination $SysCfg -Force
      & $SysExe -c $SysCfg | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Sysmon -c KO ($LASTEXITCODE)" }
    } else {
      Remove-Item -LiteralPath $SysCfgNew -Force
      Step "Sysmon present, configuration inchangee"
    }
    if ((Get-Service Sysmon64).Status -ne "Running") { Start-Service Sysmon64 }
    $Report["Sysmon"] = "OK service $((Get-Service Sysmon64).Status)"
  }
} catch { $Report["Sysmon"] = "KO $($_.Exception.Message)" }

# ============================ 3. WINLOGBEAT ===================================
$NeedRestart = $false
$BeatExe = Join-Path $InstallDir "winlogbeat.exe"
$YmlCur = Join-Path $InstallDir "winlogbeat.yml"
$WinlogbeatOk = $false
try {
  # --- service existant : meme repertoire et meme configuration attendus ---
  $ExistingSvc = Get-CimInstance Win32_Service -Filter "Name='winlogbeat'" -ErrorAction SilentlyContinue
  if ($ExistingSvc -and $ExistingSvc.PathName -notmatch [regex]::Escape($BeatExe)) {
    throw "Service winlogbeat installe ailleurs ($($ExistingSvc.PathName)) : migration manuelle requise"
  }

  # --- binaire : version cible, jamais de retour en arriere ---
  $Installed = ""
  if (Test-Path -LiteralPath $BeatExe) { $Installed = Get-OmniBeatVersion ((& $BeatExe version 2>&1) | Out-String) }
  $Target = $WinlogbeatVersion
  if ($Installed -and ([version]$Installed -gt [version]$Target)) {
    Step "Winlogbeat $Installed plus recent que la cible $Target : conserve"
    $Target = $Installed
  }
  $TestExe = $BeatExe
  $TestHome = $InstallDir
  if ($Installed -ne $Target -or $Simulation) {
    $ZipName = ""
    foreach ($candidate in @("winlogbeat-oss-$Target-windows-x86_64.zip", "winlogbeat-$Target-windows-x86_64.zip")) {
      if ($KitChecksums.ContainsKey($candidate)) { $ZipName = $candidate; break }
    }
    if (-not $ZipName -and $Installed -ne $Target) { throw "Archive Winlogbeat $Target absente du kit" }
    if ($ZipName) {
      $Zip = Join-Path $Staging $ZipName
      Get-KitFile $ZipName $Zip
      $Tmp = Join-Path $Staging "wlb-extract"
      Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
      Expand-Archive -LiteralPath $Zip -DestinationPath $Tmp -Force
      $Inner = Get-ChildItem -LiteralPath $Tmp -Directory | Select-Object -First 1
      if (-not $Inner) { throw "Archive Winlogbeat vide : $ZipName" }
      $NewExe = Join-Path $Inner.FullName "winlogbeat.exe"
      Assert-Signature $NewExe "Elasticsearch"
      $TestExe = $NewExe
      $TestHome = $Inner.FullName
      if ($Installed -ne $Target -and -not $Simulation) {
        Step "Deploiement Winlogbeat $Target (present : '$Installed')"
        if (Get-Service winlogbeat -ErrorAction SilentlyContinue) { Stop-Service winlogbeat -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Copy-Item -Path (Join-Path $Inner.FullName "*") -Destination $InstallDir -Recurse -Force
        Set-Content -LiteralPath (Join-Path $InstallDir "version.txt") -Value $Target
        $NeedRestart = $true
        $TestExe = $BeatExe
        $TestHome = $InstallDir
      }
    }
  }

  # --- configuration : kit + canal Veeam si serveur Veeam B&R detecte ---
  $YmlNew = Join-Path $Staging "winlogbeat.new.yml"
  Get-KitFile "winlogbeat.yml" $YmlNew
  if (Get-WinEvent -ListLog "Veeam Backup" -ErrorAction SilentlyContinue) {
    Step "Journal 'Veeam Backup' detecte -> ajout du canal a la conf locale"
    $VeeamBlock = "`n`n  # --- Veeam Backup & Replication (serveur Veeam detecte ici) --------------`n  - name: Veeam Backup`n    ignore_older: 72h"
    $text = [IO.File]::ReadAllText($YmlNew) -replace "(?m)^winlogbeat\.event_logs:", ("winlogbeat.event_logs:" + $VeeamBlock)
    [IO.File]::WriteAllText($YmlNew, $text, (New-Object System.Text.UTF8Encoding($false)))
  }
  $ConfChanged = ((Get-HashOrEmpty $YmlNew) -ne (Get-HashOrEmpty $YmlCur))

  # --- validation de la NOUVELLE configuration avant de la poser ---
  if ($ConfChanged -or $Simulation) {
    if (-not (Test-Path -LiteralPath $TestExe)) { throw "winlogbeat.exe indisponible pour valider la configuration" }
    $Test = & $TestExe test config -c $YmlNew --path.home $TestHome --path.data (Join-Path $Staging "wlb-test-data") 2>&1
    if ($LASTEXITCODE -ne 0) { throw "winlogbeat test config KO, configuration actuelle conservee : $($Test | Out-String)" }
  }

  # --- certificat de la sortie Beats ---
  $CaCur = Join-Path $InstallDir $BeatsCaName
  $CaChanged = ((Get-HashOrEmpty $CaFile) -ne (Get-HashOrEmpty $CaCur))

  if ($Simulation) {
    $todo = @()
    if ($Installed -ne $Target) { $todo += "binaire $Installed -> $Target" }
    if ($ConfChanged) { $todo += "configuration" }
    if ($CaChanged) { $todo += "certificat" }
    if (-not $ExistingSvc) { $todo += "service a creer" }
    if ($todo.Count) { $Report["Winlogbeat"] = "OK test config valide ; changements : " + ($todo -join ", ") }
    else { $Report["Winlogbeat"] = "OK test config valide ; rien a changer" }
  } else {
    if ($ConfChanged) {
      Step "Configuration winlogbeat differente -> application (ancienne conservee en .precedent)"
      if (Test-Path -LiteralPath $YmlCur) { Copy-Item -LiteralPath $YmlCur -Destination "$YmlCur.precedent" -Force }
      Copy-Item -LiteralPath $YmlNew -Destination $YmlCur -Force
      $NeedRestart = $true
    } else { Step "Configuration winlogbeat inchangee" }
    if ($CaChanged) { Copy-Item -LiteralPath $CaFile -Destination $CaCur -Force; $NeedRestart = $true }

    if (-not $ExistingSvc) {
      Step "Creation du service winlogbeat"
      $BinPath = ('"{0}\winlogbeat.exe" --environment=windows_service ' +
                  '-c "{0}\winlogbeat.yml" ' +
                  '--path.home "{0}" --path.data "C:\ProgramData\winlogbeat" ' +
                  '--path.logs "C:\ProgramData\winlogbeat\logs" -E logging.files.redirect_stderr=true') -f $InstallDir
      New-Service -Name winlogbeat -DisplayName "Winlogbeat (SIEM)" -BinaryPathName $BinPath -StartupType Automatic | Out-Null
      & sc.exe failure winlogbeat reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
      $NeedRestart = $true
    }

    $SvcState = (Get-Service winlogbeat).Status
    if ($SvcState -ne "Running") { Start-Service winlogbeat; Step "Service demarre" }
    elseif ($NeedRestart) { Restart-Service winlogbeat -Force; Step "Service redemarre (changements appliques)" }
    else { Step "Service deja demarre, rien a redemarrer" }
    $Report["Winlogbeat"] = "OK $Target, service $((Get-Service winlogbeat).Status)"
  }
  $WinlogbeatOk = $true
} catch { $Report["Winlogbeat"] = "KO $($_.Exception.Message)" }
Remove-Item -LiteralPath (Join-Path $Staging "wlb-extract"), (Join-Path $Staging "wlb-test-data") -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath $Staging -Filter "winlogbeat-*.zip" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $Staging "winlogbeat.new.yml") -Force -ErrorAction SilentlyContinue

# ============================ 4. SANTE ========================================
if ($Simulation) {
  $Report["Sortie $BeatsPort"] = "OK non testee en simulation"
} elseif ($WinlogbeatOk) {
  try {
    $Established = $null
    $deadline = (Get-Date).AddSeconds(30)
    do {
      $proc = Get-Process -Name winlogbeat -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($proc) {
        $Established = Get-NetTCPConnection -OwningProcess $proc.Id -RemotePort $BeatsPort -State Established -ErrorAction SilentlyContinue |
          Select-Object -First 1
      }
      if ($Established) { break }
      Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    if ($Established) {
      $Report["Sortie $BeatsPort"] = "OK connexion etablie vers $($Established.RemoteAddress):$BeatsPort"
    } else {
      # Diagnostic seulement : aucune connexion etablie par le service.
      $Out = & $BeatExe test output -c $YmlCur --path.home $InstallDir 2>&1
      $Err = ($Out | Select-String "error|ERROR|fail" | Select-Object -First 1)
      throw "aucune connexion etablie vers le SIEM ; test output : $Err"
    }
  } catch { $Report["Sortie $BeatsPort"] = "KO $($_.Exception.Message)" }

  try {
    $LogFile = Get-ChildItem -LiteralPath "C:\ProgramData\winlogbeat\logs" -Filter "winlogbeat*" -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $LogFile) { throw "aucun fichier de log winlogbeat trouve" }
    $Since = (Get-Date).ToUniversalTime().AddMinutes(-10)
    $BadLines = @(Get-Content -LiteralPath $LogFile.FullName -Tail 300 | Where-Object {
      $_ -match '"log\.level":"error"' -and
      ($_ -notmatch '"@timestamp":"(?<ts>[^"]+)"' -or
       ([datetime]::Parse($Matches.ts, [Globalization.CultureInfo]::InvariantCulture,
         [Globalization.DateTimeStyles]::AdjustToUniversal) -gt $Since))
    })
    $ChannelErr = $BadLines | Where-Object { $_ -match "invalide|invalid query|Open\(\) error" } | Select-Object -First 1
    if ($ChannelErr) { throw ("erreur d'ouverture de canal : " + $ChannelErr.Substring(0, [Math]::Min(180, $ChannelErr.Length))) }
    if ($BadLines.Count -gt 0) { $Report["Canaux"] = "KO $($BadLines.Count) erreur(s) recente(s) dans les logs winlogbeat" }
    else {
      $NbCanaux = @(Select-String -LiteralPath $YmlCur -Pattern "^\s*- name:").Count
      $Report["Canaux"] = "OK $NbCanaux canaux configures, aucune erreur de lecture"
    }
  } catch { $Report["Canaux"] = "KO $($_.Exception.Message)" }
}

# ===================== 5. INVENTAIRE (vulnerabilites) ========================
try {
  $InvPs = Join-Path $LiveDir "Get-OmniInventory.ps1"
  $InvNew = Join-Path $Staging "Get-OmniInventory.new.ps1"
  Get-KitFile "Get-OmniInventory.ps1" $InvNew
  $InvChanged = ((Get-HashOrEmpty $InvNew) -ne (Get-HashOrEmpty $InvPs))
  $TaskName = "OMNI-Inventory"
  $ExpectedArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$InvPs`""
  $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  $TaskOk = $false
  if ($Task) {
    $a = @($Task.Actions)[0]
    $TaskOk = ($a.Execute -eq "powershell.exe" -and $a.Arguments -eq $ExpectedArgs -and $Task.Principal.UserId -match 'SYSTEM')
  }
  if ($Simulation) {
    Remove-Item -LiteralPath $InvNew -Force -ErrorAction SilentlyContinue
    $msg = @()
    if (-not $TaskOk) { $msg += "tache a creer" }
    if ($InvChanged) { $msg += "script a mettre a jour" }
    if ($msg.Count) { $Report["Inventaire"] = "OK " + ($msg -join ", ") } else { $Report["Inventaire"] = "OK tache et script a jour" }
  } else {
    if ($InvChanged) { Move-Item -LiteralPath $InvNew -Destination $InvPs -Force } else { Remove-Item -LiteralPath $InvNew -Force }
    if (-not $TaskOk) {
      Step "Creation de la tache $TaskName (une seule fois)"
      if (-not [Diagnostics.EventLog]::SourceExists("OMNI-Inventory")) {
        New-EventLog -LogName "OMNI-Inventaire" -Source "OMNI-Inventory"
      }
      $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $ExpectedArgs
      $trg = New-ScheduledTaskTrigger -Daily -At 2:00am
      # Heure locale sans decalage fige : la tache suit les changements d'heure.
      $trg.StartBoundary = (Get-Date -Hour 2 -Minute 0 -Second 0).ToString("yyyy-MM-dd'T'HH:mm:ss")
      $prn = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
      if ($Task) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
      Register-ScheduledTask -TaskName $TaskName -Action $act -Trigger $trg -Principal $prn `
        -Description "Inventaire logiciel/OS -> SIEM (vulnerabilites)" | Out-Null
    }
    if ($InvChanged -or -not $TaskOk) {
      & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InvPs *> $null
      $Report["Inventaire"] = "OK tache $TaskName en place, inventaire emis"
    } else { $Report["Inventaire"] = "OK tache $TaskName et script inchanges" }
  }
} catch { $Report["Inventaire"] = "KO $($_.Exception.Message)" }

Finish 0
