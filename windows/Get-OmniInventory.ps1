<#
.SYNOPSIS
  Get-OmniInventory.ps1 - Inventaire logiciel + OS/correctifs -> SIEM.
  Alimente la detection de vulnerabilites (CISA KEV) et l'anciennete des
  correctifs, cote SIEM (script serveur omni-vuln-scan).

.DESCRIPTION
  Enumere :
   - les LOGICIELS installes (cles de desinstallation 64 + 32 bits, hors
     composants systeme) : nom + version + editeur ;
   - l'OS et les CORRECTIFS : edition, build, dernier KB, date du dernier
     correctif, nombre de hotfix.
  Chaque element est ecrit dans un journal Windows dedie "OMNI-Inventaire"
  (EventID 9101 = logiciel, 9102 = OS/correctifs), collecte par Winlogbeat
  (canal a ajouter a winlogbeat.yml) -> le SIEM le parse (event_source=inventory).
  Aucun flux reseau nouveau (passe par Winlogbeat comme le reste).

  A planifier via NinjaOne / tache planifiee, QUOTIDIEN, en SYSTEM.
  Format des messages = key=value separes par "|" (parse par le pipeline).

.NOTES
  Executer en administrateur. Compatible Windows FR (dates en ISO yyyy-MM-dd).
#>
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
$LogName = "OMNI-Inventaire"; $Source = "OMNI-Inventory"
$Host7   = $env:COMPUTERNAME

try {
  if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
    New-EventLog -LogName $LogName -Source $Source
    # journal circulaire suffisant (l'inventaire est re-emis a chaque execution)
    Limit-EventLog -LogName $LogName -MaximumSize 8MB -OverflowAction OverwriteAsNeeded -ErrorAction SilentlyContinue
  }
} catch { Write-Host "[!] journal: $($_.Exception.Message)" }

function Emit($eid, $msg) {
  Write-EventLog -LogName $LogName -Source $Source -EventId $eid -EntryType Information -Message $msg
}

# --- 1. OS + correctifs ------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$hf = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } |
        Sort-Object InstalledOn -Descending)
$last = if ($hf.Count) { $hf[0] } else { $null }
$lastDate = if ($last) { $last.InstalledOn.ToString('yyyy-MM-dd') } else { "" }
$lastKb   = if ($last) { "$($last.HotFixID)" } else { "" }
Emit 9102 ("os_caption=$($os.Caption)|os_build=$($os.BuildNumber)|os_version=$($os.Version)|os_last_kb=$lastKb|os_last_patch=$lastDate|os_hotfix_count=$($hf.Count)")

# --- 2. Logiciels installes (registre Uninstall) -----------------------------
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$seen = @{}; $n = 0
foreach ($p in $paths) {
  Get-ItemProperty $p -ErrorAction SilentlyContinue | ForEach-Object {
    $name = "$($_.DisplayName)".Trim()
    if (-not $name) { return }
    if ($_.SystemComponent -eq 1) { return }      # composants systeme -> ignore
    if (-not $_.DisplayVersion -and -not $_.Publisher) { return }  # entrees vides
    $ver = ("$($_.DisplayVersion)").Trim()
    $pub = ("$($_.Publisher)").Trim()
    # nettoyage des separateurs pour ne pas casser le parsing key=value|...
    $name = $name -replace '[|=]', ' '
    $ver  = $ver  -replace '[|=]', ' '
    $pub  = $pub  -replace '[|=]', ' '
    $key = "$name|$ver"
    if ($seen.ContainsKey($key)) { return }
    $seen[$key] = $true
    Emit 9101 ("inv_product=$name|inv_version=$ver|inv_publisher=$pub")
    $n++
  }
}

Write-Host "Inventaire emis : 1 evenement OS + $n logiciels (journal $LogName) pour $Host7."
