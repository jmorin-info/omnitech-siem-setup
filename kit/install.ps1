<#
.SYNOPSIS
  install.ps1 - Enrolement SIEM (Windows), STANDALONE, en one-liner.

.DESCRIPTION
  A lancer a la main sur n'importe quel poste/serveur Windows :
      irm https://<siem-fqdn>/kit/install.ps1 | iex

  Ce script est un WRAPPER leger qui :
    (a) VERIFIE les prerequis (PowerShell 5.1+, OS 64-bit, TCP 5044+443 vers le
        SIEM, espace disque) AVANT de toucher au systeme ;
    (b) s'AUTO-ELEVE en administrateur si lance en utilisateur (UAC) ;
    (c) recupere le coeur Install-OmniSiem-NinjaOne.ps1 en HTTPS valide, verifie
        son empreinte dans SHA256SUMS, puis l'INVOQUE (certificat -> audit ->
        Sysmon -> Winlogbeat -> sante -> inventaire) ;
    (d) renvoie l'exit code du coeur (0 si tout OK, 1 sinon).

  -Simulation : ne modifie rien (ni elevation, ni service) ; le coeur verifie le
  kit et valide la configuration dans un repertoire temporaire.

  Le coeur ecrit son journal dans C:\ProgramData\OMNI-SIEM\install.log.

.NOTES
  Compatible Windows PowerShell 5.1 et PowerShell 7. Aucun module requis.
  Le certificat HTTPS du SIEM doit etre reconnu par Windows (CA du site deployee
  par GPO/RMM, ou certificat public) : aucune validation n'est desactivee.
#>
[CmdletBinding()]
param(
  [string]$SiemFqdn = "__SIEM_FQDN__",
  [switch]$SkipAudit,
  [switch]$Simulation
)
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Fail([string]$m) { Write-Host "[KO] $m" -ForegroundColor Red; exit 1 }
if ($SiemFqdn -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]+$') { Fail "FQDN du SIEM invalide : $SiemFqdn" }
$Base = "https://$SiemFqdn/kit"
Write-Host "=== Enrolement SIEM (Windows) - $env:COMPUTERNAME ===" -ForegroundColor Cyan

# --- (b) AUTO-ELEVATION ------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $Simulation -and -not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "[*] Droits administrateur requis -> relance elevee (UAC)..." -ForegroundColor Yellow
  $inner = "irm $Base/install.ps1 | iex"
  Start-Process powershell.exe -Verb RunAs `
    -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $inner
  return
}

# --- (a) PREREQUIS -----------------------------------------------------------
$problems = @()
if ($PSVersionTable.PSVersion.Major -lt 5) { $problems += "PowerShell 5.1+ requis (trouve $($PSVersionTable.PSVersion))" }
if (-not [Environment]::Is64BitOperatingSystem) { $problems += "OS 64-bit requis" }
foreach ($port in 5044, 443) {
  $r = Test-NetConnection -ComputerName $SiemFqdn -Port $port -WarningAction SilentlyContinue
  if (-not $r.TcpTestSucceeded) { $problems += "TCP $port injoignable vers $SiemFqdn (firewall/VLAN/VPN ?)" }
}
try { $free = (Get-PSDrive C -ErrorAction Stop).Free / 1GB; if ($free -lt 1) { $problems += ("Disque C: insuffisant ({0:N1} Go libres)" -f $free) } } catch { }
if ($problems.Count) { Fail ("Prerequis non satisfaits :`n - " + ($problems -join "`n - ")) }
Write-Host ("[OK] Prerequis valides (PS {0}, 64-bit, 5044+443 OK)" -f $PSVersionTable.PSVersion) -ForegroundColor Green

# --- (c) RECUP DU COEUR (HTTPS valide + empreinte obligatoire) ----------------
if ($Simulation) { $Staging = Join-Path $env:TEMP "OMNI-SIEM-simulation" } else { $Staging = Join-Path $env:ProgramData "OMNI-SIEM" }
New-Item -ItemType Directory -Path $Staging -Force | Out-Null
$Core = Join-Path $Staging "Install-OmniSiem-NinjaOne.ps1"
$Temp = Join-Path $Staging ([guid]::NewGuid().ToString() + ".ps1")
try {
  if ($null -ne [Net.ServicePointManager]::ServerCertificateValidationCallback) {
    Fail "Validation TLS personnalisee detectee dans la session : refus"
  }
  $Sums = Join-Path $Staging "SHA256SUMS"
  Invoke-WebRequest -Uri "$Base/SHA256SUMS" -OutFile $Sums -UseBasicParsing -TimeoutSec 60
  $entries = @(Get-Content -LiteralPath $Sums | ForEach-Object { $_.TrimStart([char]0xFEFF) } |
    Where-Object { $_ -match '^[0-9a-fA-F]{64}\s+\*?(?:\./)?Install-OmniSiem-NinjaOne\.ps1\s*$' })
  if ($entries.Count -ne 1) { Fail "SHA256SUMS : entree du coeur absente ou ambigue" }
  $want = ($entries[0] -split '\s+')[0].ToUpperInvariant()
  Invoke-WebRequest -Uri "$Base/Install-OmniSiem-NinjaOne.ps1" -OutFile $Temp -UseBasicParsing -TimeoutSec 120
  $got = (Get-FileHash -LiteralPath $Temp -Algorithm SHA256).Hash.ToUpperInvariant()
  if ($got -ne $want) { Fail "Integrite du coeur invalide (SHA256 attendu $want, obtenu $got)" }
  Move-Item -LiteralPath $Temp -Destination $Core -Force
  Write-Host "[OK] HTTPS et empreinte SHA256 du coeur verifies" -ForegroundColor Green
} catch {
  Fail "Telechargement ou verification du kit impossible : $($_.Exception.Message)"
} finally {
  Remove-Item -LiteralPath $Temp -Force -ErrorAction SilentlyContinue
}

# --- (d) DELEGATION au coeur idempotent --------------------------------------
$coreArgs = @{ BaseUrl = $Base }
if ($SkipAudit) { $coreArgs["SkipAudit"] = $true }
if ($Simulation) { $coreArgs["Simulation"] = $true; $coreArgs["StagingDir"] = $Staging }
$global:LASTEXITCODE = 1
& $Core @coreArgs
exit $LASTEXITCODE
