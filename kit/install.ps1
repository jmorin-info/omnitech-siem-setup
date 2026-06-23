<#
.SYNOPSIS
  install.ps1 - Enrolement SIEM OMNITECH (Windows), STANDALONE, en one-liner.

.DESCRIPTION
  A lancer a la main sur n'importe quel poste/serveur Windows :
      irm https://bx-it-graylog-vm.omnitech.security/kit/install.ps1 | iex

  Ce script est un WRAPPER leger qui :
    (a) VERIFIE les prerequis (PowerShell 5.1+, OS 64-bit, TCP 5044+443 vers le
        SIEM, espace disque) AVANT de toucher au systeme ;
    (b) s'AUTO-ELEVE en administrateur si lance en utilisateur (UAC) ;
    (c) recupere puis INVOQUE le coeur idempotent Install-OmniSiem-NinjaOne.ps1
        (CA TOFU -> audit -> Sysmon -> Winlogbeat -> sante -> inventaire) ;
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
  [string]$SiemFqdn = "bx-it-graylog-vm.omnitech.security",
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

# --- (c) RECUP DU COEUR (TOFU sur le CA le temps du 1er appel) ----------------
$Staging = "$env:ProgramData\OMNI-SIEM"
New-Item -ItemType Directory -Path $Staging -Force | Out-Null
$Core = Join-Path $Staging "Install-OmniSiem-NinjaOne.ps1"
$cb = [Net.ServicePointManager]::ServerCertificateValidationCallback
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }   # TOFU : le CA n'est pas encore pinne
try {
  Invoke-WebRequest -Uri "$Base/Install-OmniSiem-NinjaOne.ps1" -OutFile $Core -UseBasicParsing
  # Verification d'integrite optionnelle via SHA256SUMS (genere par 95-kit-deploy.sh)
  try {
    $sums = (Invoke-WebRequest -Uri "$Base/SHA256SUMS" -UseBasicParsing).Content
    $want = ($sums -split "`n" | Where-Object { $_ -match 'Install-OmniSiem-NinjaOne\.ps1' } |
             ForEach-Object { ($_ -split '\s+')[0] }) | Select-Object -First 1
    if ($want) {
      $got = (Get-FileHash -Path $Core -Algorithm SHA256).Hash
      if ($got -ne $want.ToUpper()) { Fail "Integrite du coeur invalide (SHA256 attendu $want, obtenu $got)" }
      Write-Host "[OK] Integrite du coeur verifiee (SHA256)" -ForegroundColor Green
    }
  } catch { Write-Host "[*] SHA256SUMS indisponible - integrite non verifiee (TLS+CA TOFU seuls)" -ForegroundColor Yellow }
}
finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $cb }
if (-not (Test-Path $Core) -or (Get-Item $Core).Length -eq 0) { Fail "Telechargement du coeur vide" }

# --- (d) DELEGATION au coeur idempotent --------------------------------------
$coreArgs = @{ BaseUrl = $Base }
if ($SkipAudit) { $coreArgs["SkipAudit"] = $true }
& $Core @coreArgs
exit $LASTEXITCODE
