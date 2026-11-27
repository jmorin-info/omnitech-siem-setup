<#
.SYNOPSIS
  install.ps1 - Enrolement SIEM OMNITECH (Windows), STANDALONE, en one-liner.

.DESCRIPTION
  A lancer a la main sur n'importe quel poste/serveur Windows :
      irm https://<siem-fqdn>/kit/install.ps1 | iex

  Ce script est un WRAPPER leger qui :
    (a) VERIFIE les prerequis (PowerShell 5.1+, OS 64-bit, TCP 5044+443 vers le
        SIEM, espace disque) AVANT de toucher au systeme ;
    (b) s'AUTO-ELEVE en administrateur si lance en utilisateur (UAC) ;
    (c) recupere puis INVOQUE le coeur idempotent Install-OmniSiem-NinjaOne.ps1
        (certificat verifie -> audit -> Sysmon -> Winlogbeat -> sante -> inventaire) ;
    (d) renvoie l'exit code du coeur (0 si tout OK, 1 sinon).

  Le coeur ecrit son journal dans C:\ProgramData\OMNI-SIEM\install.log et fait
  tout le travail reel (deja idempotent, hash-compare, exit 0/1). Ce wrapper
  n'enleve rien : il prefixe les prerequis + l'elevation que NinjaOne (SYSTEM)
  n'avait pas besoin de faire.

.NOTES
  Compatible Windows PowerShell 5.1. Aucun module requis. Reseau interne VPN-only.
#>
[CmdletBinding()]
param(
  [string]$SiemFqdn = "__SIEM_FQDN__",
  [switch]$SkipAudit
)
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Base = "https://$SiemFqdn/kit"

function Fail($m){ Write-Host "[KO] $m" -ForegroundColor Red; exit 1 }
Write-Host "=== Enrolement SIEM OMNITECH (Windows) - $env:COMPUTERNAME ===" -ForegroundColor Cyan

# --- (b) AUTO-ELEVATION ------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "[*] Droits administrateur requis -> relance elevee (UAC)..." -ForegroundColor Yellow
  $inner = "irm $Base/install.ps1 | iex"
  Start-Process powershell.exe -Verb RunAs `
    -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-Command",$inner
  return
}

# --- (a) PREREQUIS -----------------------------------------------------------
$problems = @()
if ($PSVersionTable.PSVersion.Major -lt 5) { $problems += "PowerShell 5.1+ requis (trouve $($PSVersionTable.PSVersion))" }
if (-not [Environment]::Is64BitOperatingSystem)  { $problems += "OS 64-bit requis" }
foreach ($port in 5044,443) {
  $r = Test-NetConnection -ComputerName $SiemFqdn -Port $port -WarningAction SilentlyContinue
  if (-not $r.TcpTestSucceeded) { $problems += "TCP $port injoignable vers $SiemFqdn (firewall/VLAN/VPN ?)" }
}
try { $free = (Get-PSDrive C -ErrorAction Stop).Free / 1GB; if ($free -lt 1) { $problems += ("Disque C: insuffisant ({0:N1} Go libres)" -f $free) } } catch {}
if ($problems.Count) { Fail ("Prerequis non satisfaits :`n - " + ($problems -join "`n - ")) }
Write-Host ("[OK] Prerequis valides (admin, PS {0}, 64-bit, 5044+443 OK)" -f $PSVersionTable.PSVersion) -ForegroundColor Green

# --- (c) RECUP DU COEUR (HTTPS valide + empreinte obligatoire) ----------------
$Staging = "$env:ProgramData\OMNI-SIEM"
New-Item -ItemType Directory -Path $Staging -Force | Out-Null
$Core = Join-Path $Staging "Install-OmniSiem-NinjaOne.ps1"
try {
  # Keep normal Windows certificate validation enabled. Sites using a private
  # CA must deploy that CA through their endpoint-management system first.
  Invoke-WebRequest -Uri "$Base/SHA256SUMS" -OutFile (Join-Path $Staging "SHA256SUMS") -UseBasicParsing
  Invoke-WebRequest -Uri "$Base/Install-OmniSiem-NinjaOne.ps1" -OutFile $Core -UseBasicParsing

  $sumLine = Get-Content (Join-Path $Staging "SHA256SUMS") |
    Where-Object { $_ -match '^[0-9a-fA-F]{64}\s+\*?Install-OmniSiem-NinjaOne\.ps1\s*$' } |
    Select-Object -First 1
  if (-not $sumLine) { Fail "SHA256SUMS absent ou sans entree valide pour Install-OmniSiem-NinjaOne.ps1" }
  $want = ($sumLine -split '\s+')[0].ToUpperInvariant()
  $got = (Get-FileHash -Path $Core -Algorithm SHA256).Hash.ToUpperInvariant()
  if ($got -ne $want) { Fail "Integrite du coeur invalide (SHA256 attendu $want, obtenu $got)" }
  Write-Host "[OK] Integrite du coeur verifiee (SHA256)" -ForegroundColor Green
} catch {
  Fail "Telechargement ou verification du kit impossible : $($_.Exception.Message)"
}
if (-not (Test-Path $Core) -or (Get-Item $Core).Length -eq 0) { Fail "Telechargement du coeur vide" }

# --- (d) DELEGATION au coeur idempotent --------------------------------------
$coreArgs = @{ BaseUrl = $Base }
if ($SkipAudit) { $coreArgs["SkipAudit"] = $true }
& $Core @coreArgs
exit $LASTEXITCODE
