<#
.SYNOPSIS
  Get-OmniCertExpiry.ps1 - Surveille l'expiration des certificats et remonte au SIEM.

.DESCRIPTION
  Deux modes, AUTO-detectes :
   - Sur la PKI (role AD CS present) : interroge la BASE DE DONNEES DE LA CA et
     remonte TOUS les certificats EMIS (non revoques) qui expirent bientot.
     -> vue exhaustive de tout le parc en un seul deploiement.
   - Sur une machine ordinaire : enumere le magasin LocalMachine\My (certs
     installes localement, y compris tiers/auto-signes).

  Chaque certificat proche de l'expiration est ecrit dans un journal Windows
  dedie "OMNI-Certificats" (EventID 9001), collecte par Winlogbeat (canal ajoute
  a winlogbeat.yml) -> le SIEM detecte et alerte. Aucun flux reseau nouveau.

  Idempotent. A planifier via NinjaOne (quotidien), idealement sur la PKI
  (10.33.50.248) + eventuellement les serveurs critiques.

.PARAMETER WarnDays
  Seuil d'alerte en jours (defaut 60). Les certs expirant sous ce seuil sont remontes.

.NOTES
  Executer en administrateur (lecture CA database / magasin machine).
#>
[CmdletBinding()]
param([int]$WarnDays = 60)
$ErrorActionPreference = "Stop"
$LogName = "OMNI-Certificats"; $Source = "OMNI-CertMonitor"
$Host7   = $env:COMPUTERNAME

# --- journal Windows dedie (cree une fois) -----------------------------------
try {
  if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
    New-EventLog -LogName $LogName -Source $Source
  }
} catch { Write-Host "[!] creation du journal: $($_.Exception.Message)" }

function Emit($subject, $store, $expiry, $days, $extra) {
  $msg = "CERT_EXPIRE | machine=$Host7 | store=$store | subject=$subject | expiry=$($expiry.ToString('yyyy-MM-dd')) | days=$days | $extra"
  $level = if ($days -lt 15) { "Error" } else { "Warning" }
  Write-EventLog -LogName $LogName -Source $Source -EventId 9001 -EntryType $level -Message $msg
  Write-Host "  [$days j] $subject"
}

$now = Get-Date; $limit = $now.AddDays($WarnDays); $n = 0

# --- MODE PKI : base de donnees de la CA -------------------------------------
$isCA = (Get-Service CertSvc -ErrorAction SilentlyContinue) -ne $null
if ($isCA) {
  Write-Host "Mode PKI (base CA) - certificats emis expirant sous $WarnDays j :"
  $caParsed = 0
  # --- METHODE 1 : interface COM ICertView (robuste, sans CLI ni locale) -----
  # C'est l'API native du role AD CS : pas de parsing texte, pas de probleme de
  # langue ni de format de date. On lit la base, colonnes CommonName + NotAfter,
  # restreint aux certificats EMIS (Disposition == 20).
  try {
    $caName = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -ErrorAction Stop).Active
    $config = "$env:COMPUTERNAME\$caName"
    $view = New-Object -ComObject CertificateAuthority.View
    $view.OpenConnection($config)
    $iDisp = $view.GetColumnIndex($false, "Disposition")
    $iCN   = $view.GetColumnIndex($false, "CommonName")
    $iNA   = $view.GetColumnIndex($false, "NotAfter")
    $view.SetResultColumnCount(2)
    $view.SetResultColumn($iCN); $view.SetResultColumn($iNA)
    $view.SetRestriction($iDisp, 1, 0, 20)   # CVR_SEEK_EQ=1 -> Disposition==20
    $rowEnum = $view.OpenView()
    # collecte d'abord, emet ensuite : si l'enumeration casse en cours, on bascule
    # proprement sur le repli sans double comptage.
    $found = New-Object System.Collections.ArrayList
    while ($rowEnum.Next() -ge 0) {
      $cn = ""; $na = $null
      $colEnum = $rowEnum.EnumCertViewColumn()
      while ($colEnum.Next() -ge 0) {
        $cName = $colEnum.GetName(); $cVal = $colEnum.GetValue(0)
        if ($cName -like "*CommonName*") { $cn = "$cVal" }
        elseif ($cName -like "*NotAfter*") { $na = $cVal }
      }
      if ($na) { [void]$found.Add(@{ cn = "$cn".Trim(); d = [datetime]$na }) }
    }
    foreach ($f in $found) {
      $caParsed++
      $days = [int]([math]::Floor(($f.d - $now).TotalDays))
      if ($f.cn -and $days -ge 0 -and $days -lt $WarnDays) { Emit $f.cn "CA-database" $f.d $days ""; $n++ }
    }
    Write-Host "  ($caParsed certificat(s) lus dans la base CA)"
  } catch {
    Write-Host "  [DIAG] Lecture COM impossible : $($_.Exception.Message)"
    # --- METHODE 2 (repli) : certutil CSV, en capturant l'erreur exacte ------
    $rows = certutil -view -restrict "Disposition=20" -out "CommonName,NotAfter" csv 2>&1
    foreach ($line in $rows) {
      $t = "$line".Trim(); if (-not $t) { continue }
      $cells = [regex]::Matches($t, '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value }
      if ($cells.Count -lt 2) { continue }
      $d = [datetime]::MinValue
      if ([datetime]::TryParse($cells[1].Trim(), [Globalization.CultureInfo]::CurrentCulture, [Globalization.DateTimeStyles]::None, [ref]$d) -or `
          [datetime]::TryParse($cells[1].Trim(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) {
        $caParsed++
        $days = [int]([math]::Floor(($d - $now).TotalDays))
        if ($cells[0].Trim() -and $days -ge 0 -and $days -lt $WarnDays) { Emit ($cells[0].Trim()) "CA-database" $d $days ""; $n++ }
      }
    }
    if ($caParsed -eq 0) {
      Write-Host "  [DIAG] certutil aussi en echec - sortie brute (12 lignes) :"
      $rows | Select-Object -First 12 | ForEach-Object { Write-Host "  DIAG| $_" }
    } else { Write-Host "  ($caParsed certificat(s) lus via certutil)" }
  }
}

# --- MODE LOCAL : magasin de la machine (toujours, en complement) ------------
Write-Host "Magasin LocalMachine\My - certs expirant sous $WarnDays j :"
Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | ForEach-Object {
  if ($_.NotAfter -le $limit -and $_.NotAfter -ge $now) {
    $days = [int]([math]::Floor(($_.NotAfter - $now).TotalDays))
    $thumb = $_.Thumbprint.Substring(0,8)
    # nom lisible : CN du sujet, sinon FriendlyName, sinon empreinte
    $nm = ($_.Subject -replace '^CN=','' -replace ',.*$','').Trim()
    if (-not $nm) { $nm = "$($_.FriendlyName)".Trim() }
    if (-not $nm) { $nm = "(sans CN) $thumb" }
    Emit $nm "LocalMachine\My" $_.NotAfter $days "thumb=$thumb"
    $n++
  }
}

Write-Host ""
Write-Host "Termine : $n certificat(s) proche(s) d'expiration remonte(s) au SIEM (canal $LogName)."
if ($n -eq 0) { Write-Host "Aucun certificat n'expire dans les $WarnDays prochains jours." }
