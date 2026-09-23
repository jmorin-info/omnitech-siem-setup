<#
.SYNOPSIS
    Hygiene du parc OMNITECH : desinstalle le superflu, met a jour le necessaire,
    applique les correctifs Windows. Concu pour NinjaOne (contexte SYSTEM).

.DESCRIPTION
    Repond au constat SIEM du 23/09/2026 : 79 hotes porteurs de vulnerabilites
    ACTIVEMENT EXPLOITEES (catalogue CISA KEV), dont 1 537 constats lies a des
    campagnes ransomware.

    Le script distingue trois familles, ce qui est tout l'enjeu :
      1. SUPERFLU   -> desinstalle (Wazuh reliquat de test, Help Viewer, SDK AXIS)
      2. NECESSAIRE -> met a jour (Chrome, Firefox, Notepad++, VLC, Acrobat, Docker...)
      3. PROTEGE    -> ne touche a rien (ESET, FortiClient, NinjaOne, pilotes Dell)
         Ces produits sont pilotes par leurs propres consoles (ESET PROTECT,
         FortiClient EMS, NinjaOne). Les mettre a jour en local creerait une
         divergence avec la console qui en a la charge.

.PARAMETER Apply
    SANS ce commutateur le script SIMULE et n'ecrit rien. C'est le mode par defaut :
    on deploie d'abord en simulation sur un groupe pilote, on lit le rapport, puis
    on rejoue avec -Apply.

.PARAMETER Scope
    All        : desinstallation + mises a jour (defaut)
    Uninstall  : desinstallation seule
    Update     : mises a jour applicatives seules
    Windows    : correctifs Windows seuls

.PARAMETER IncludeDotNetEol
    Ajoute la desinstallation des runtimes .NET en FIN DE SUPPORT (5.0, 6.0, 7.0).
    NON active par defaut : une application metier peut en dependre. A tester sur
    un pilote avant generalisation.

.PARAMETER AllowReboot
    Autorise un redemarrage si un correctif l'exige. Par defaut aucun redemarrage.

.EXAMPLE
    .\Invoke-ParcHygiene.ps1
    Simulation complete, aucun changement.

.EXAMPLE
    .\Invoke-ParcHygiene.ps1 -Apply -Scope Uninstall
    Desinstalle uniquement le superflu.

.NOTES
    Codes de sortie : 0 = OK | 1 = erreur bloquante | 2 = redemarrage requis
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [ValidateSet('All','Uninstall','Update','Windows')][string]$Scope = 'All',
    [switch]$IncludeDotNetEol,
    [switch]$AllowReboot
)

$ErrorActionPreference = 'Continue'
$script:Changes = 0; $script:Errors = 0; $script:RebootNeeded = $false
$LogDir  = Join-Path $env:ProgramData 'OMNITECH'
$LogFile = Join-Path $LogDir ("ParcHygiene_{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','OK','WARN','ERREUR','ACTION')][string]$Level = 'INFO')
    $line = "{0} [{1,-6}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    Write-Output $line
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
    if ($Level -eq 'ERREUR') { $script:Errors++ }
}

# =============================================================================
# GARDE-FOU : produits qu'on ne desinstalle JAMAIS, meme listes par erreur.
# Cette liste prime sur tout le reste : c'est le filet de securite du script.
# =============================================================================
$Protected = @(
    'ESET','FortiClient','NinjaOne','NinjaRMM','Microsoft 365 Apps','Office',
    'Teams','Defender','Dell Command','Dell Core Services','Dell Trusted Device',
    'Sysmon','Winlogbeat','Graylog','Veeam','SQL Server','Visual C\+\+',
    # Runtimes .NET ENCORE SUPPORTES : le nom reel est "Microsoft Windows Desktop
    # Runtime - 8.0.31 (x64)". Un motif ".NET Runtime - 8." ne matcherait PAS et
    # laisserait passer une suppression si la liste des cibles etait etendue.
    'Windows Desktop Runtime - (8|9|10)\.',
    'ASP\.NET Core (8|9|10)\.'
)

# =============================================================================
# 1. SUPERFLU -> desinstallation. Chaque entree est justifiee par une mesure.
# =============================================================================
$ToRemove = @(
    @{ Pattern = '^Wazuh Agent';              Raison = 'Reliquat de test : aucun input/stream Wazuh sur le SIEM, aucune donnee ingeree. Porte CVE-2025-24016 (CVSS 9.9) sur 38 hotes.'; Service = 'WazuhSvc' }
    @{ Pattern = '^Microsoft Help Viewer';    Raison = 'Reliquat Visual Studio, non utilise (10 hotes, CVSS 8).'; Service = $null }
    @{ Pattern = '^AXIS Media Parser SDK';    Raison = 'SDK camera residuel (7 hotes, CVSS 7).'; Service = $null }
)
$DotNetEol = @(
    @{ Pattern = 'Windows Desktop Runtime - 5\.0'; Raison = '.NET 5.0 : fin de support Microsoft (mai 2022).'; Service = $null }
    @{ Pattern = 'Windows Desktop Runtime - 6\.0'; Raison = '.NET 6.0 : fin de support Microsoft (novembre 2024).'; Service = $null }
    @{ Pattern = 'Windows Desktop Runtime - 7\.0'; Raison = '.NET 7.0 : fin de support Microsoft (mai 2024).'; Service = $null }
)
if ($IncludeDotNetEol) { $ToRemove += $DotNetEol }

# =============================================================================
# 2. NECESSAIRE -> mise a jour via winget (identifiants officiels).
#    ESET / FortiClient / M365 volontairement absents : consoles dediees.
# =============================================================================
$ToUpdate = @(
    @{ Id = 'Google.Chrome';        Nom = 'Google Chrome' }
    @{ Id = 'Mozilla.Firefox';      Nom = 'Mozilla Firefox' }
    @{ Id = 'Notepad++.Notepad++';  Nom = 'Notepad++' }
    @{ Id = 'VideoLAN.VLC';         Nom = 'VLC media player' }
    @{ Id = 'Adobe.Acrobat.Reader.64-bit'; Nom = 'Adobe Acrobat Reader' }
    @{ Id = 'Docker.DockerDesktop'; Nom = 'Docker Desktop' }
    @{ Id = '7zip.7zip';            Nom = '7-Zip' }
)

function Test-Protected {
    param([string]$Name)
    foreach ($p in $Protected) { if ($Name -match $p) { return $true } }
    return $false
}

function Get-InstalledSoftware {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString, PSChildName
}

function Invoke-Uninstall {
    param([psobject]$App, [string]$Raison, [string]$ServiceName)

    if (Test-Protected $App.DisplayName) {
        Write-Log "PROTEGE, ignore : $($App.DisplayName)" 'WARN'; return
    }

    Write-Log "Cible : $($App.DisplayName) $($App.DisplayVersion)" 'ACTION'
    Write-Log "   Motif : $Raison"

    if (-not $Apply) { Write-Log "   [SIMULATION] aucune action"; return }

    # Le service doit etre arrete avant la desinstallation, sinon l'installeur
    # echoue ou reclame un redemarrage.
    if ($ServiceName) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Stopped') {
            try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop; Write-Log "   service $ServiceName arrete" }
            catch { Write-Log "   impossible d'arreter $ServiceName : $($_.Exception.Message)" 'WARN' }
        }
    }

    $ok = $false
    # Cas MSI : le code produit est la cle de registre {GUID}
    if ($App.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') {
        $p = Start-Process msiexec.exe -ArgumentList "/x $($App.PSChildName) /qn /norestart" -Wait -PassThru -ErrorAction SilentlyContinue
        if ($p) {
            switch ($p.ExitCode) {
                0     { $ok = $true }
                3010  { $ok = $true; $script:RebootNeeded = $true }
                1605  { $ok = $true; Write-Log "   deja absent" }
                default { Write-Log "   msiexec code $($p.ExitCode)" 'ERREUR' }
            }
        }
    }
    else {
        # Cas EXE : on privilegie la chaine silencieuse fournie par l'editeur
        $cmd = if ($App.QuietUninstallString) { $App.QuietUninstallString } else { $App.UninstallString }
        if (-not $cmd) { Write-Log "   aucune commande de desinstallation" 'ERREUR'; return }
        if (-not $App.QuietUninstallString) { $cmd = "$cmd /S /silent /qn" }
        try {
            $p = Start-Process -FilePath 'cmd.exe' -ArgumentList "/c `"$cmd`"" -Wait -PassThru -ErrorAction Stop
            if ($p.ExitCode -in 0,3010,1605) { $ok = $true; if ($p.ExitCode -eq 3010) { $script:RebootNeeded = $true } }
            else { Write-Log "   code de sortie $($p.ExitCode)" 'ERREUR' }
        } catch { Write-Log "   echec : $($_.Exception.Message)" 'ERREUR' }
    }

    if ($ok) { Write-Log "   desinstalle" 'OK'; $script:Changes++ }
}

function Get-WingetPath {
    # En contexte SYSTEM (NinjaOne), winget n'est pas dans le PATH : il faut le
    # resoudre dans WindowsApps. Sans cela le script echoue silencieusement sur
    # tout le parc alors qu'il fonctionne en test interactif.
    $c = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $p = Get-ChildItem "$env:ProgramFiles\WindowsApps" -Filter 'winget.exe' -Recurse -ErrorAction SilentlyContinue |
         Where-Object { $_.FullName -match 'Microsoft\.DesktopAppInstaller_.*_x64__8wekyb3d8bbwe' } |
         Sort-Object FullName -Descending | Select-Object -First 1
    if ($p) { return $p.FullName }
    return $null
}

function Invoke-Updates {
    $winget = Get-WingetPath
    if (-not $winget) {
        Write-Log "winget introuvable (App Installer absent ou Windows trop ancien) : mises a jour applicatives ignorees" 'WARN'
        return
    }
    Write-Log "winget : $winget"
    foreach ($app in $ToUpdate) {
        $installed = & $winget list --id $app.Id --exact --accept-source-agreements 2>$null
        if ($LASTEXITCODE -ne 0 -or -not ($installed -match [regex]::Escape($app.Id))) {
            Write-Log "$($app.Nom) : non installe, ignore"; continue
        }
        Write-Log "Mise a jour : $($app.Nom)" 'ACTION'
        if (-not $Apply) { Write-Log "   [SIMULATION] aucune action"; continue }
        $out = & $winget upgrade --id $app.Id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Log "   a jour" 'OK'; $script:Changes++ }
        elseif ($out -match 'No available upgrade|Aucune mise') { Write-Log "   deja a jour" }
        else { Write-Log "   echec winget ($LASTEXITCODE)" 'ERREUR' }
    }

    # Microsoft 365 : passe par son propre client de mise a jour, pas par winget.
    $c2r = "$env:ProgramFiles\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
    if (Test-Path $c2r) {
        Write-Log "Mise a jour : Microsoft 365 Apps (ClickToRun)" 'ACTION'
        if ($Apply) {
            Start-Process $c2r -ArgumentList '/update user updatepromptuser=false forceappshutdown=false displaylevel=false' -ErrorAction SilentlyContinue
            Write-Log "   demandee (execution en arriere-plan)" 'OK'; $script:Changes++
        } else { Write-Log "   [SIMULATION] aucune action" }
    }
}

function Invoke-WindowsUpdate {
    Write-Log "Correctifs Windows" 'ACTION'
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result   = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        if ($result.Updates.Count -eq 0) { Write-Log "   aucun correctif en attente" 'OK'; return }
        Write-Log "   $($result.Updates.Count) correctif(s) en attente :"
        foreach ($u in $result.Updates) { Write-Log "     - $($u.Title)" }
        if (-not $Apply) { Write-Log "   [SIMULATION] aucune installation"; return }

        $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $result.Updates) {
            if (-not $u.EulaAccepted) { $u.AcceptEula() }
            [void]$toInstall.Add($u)
        }
        $downloader = $session.CreateUpdateDownloader(); $downloader.Updates = $toInstall
        [void]$downloader.Download()
        $installer = $session.CreateUpdateInstaller(); $installer.Updates = $toInstall
        $r = $installer.Install()
        Write-Log "   resultat : code $($r.ResultCode)" 'OK'
        $script:Changes++
        if ($r.RebootRequired) { $script:RebootNeeded = $true }
    } catch {
        Write-Log "   echec Windows Update : $($_.Exception.Message)" 'ERREUR'
    }
}

# =============================================================================
# Execution
# =============================================================================
Write-Log "=============================================================="
Write-Log " OMNITECH - Hygiene du parc   |   $env:COMPUTERNAME"
Write-Log " Mode : $(if ($Apply) { 'APPLICATION' } else { 'SIMULATION (aucun changement)' })   Perimetre : $Scope"
Write-Log " Journal : $LogFile"
Write-Log "=============================================================="

if (-not $Apply) {
    Write-Log "Rien ne sera modifie. Relancer avec -Apply apres lecture du rapport." 'WARN'
}

$inventory = Get-InstalledSoftware
Write-Log "$($inventory.Count) logiciel(s) recense(s)"

if ($Scope -in 'All','Uninstall') {
    Write-Log "--- Desinstallation du superflu ---"
    foreach ($t in $ToRemove) {
        $found = $inventory | Where-Object { $_.DisplayName -match $t.Pattern }
        if (-not $found) { continue }
        foreach ($app in $found) { Invoke-Uninstall -App $app -Raison $t.Raison -ServiceName $t.Service }
    }
    if (-not $IncludeDotNetEol) {
        $eol = $inventory | Where-Object { $_.DisplayName -match 'Windows Desktop Runtime - [567]\.0' }
        if ($eol) {
            Write-Log "$($eol.Count) runtime(s) .NET en fin de support detecte(s) mais NON traite(s)." 'WARN'
            Write-Log "   Relancer avec -IncludeDotNetEol apres validation sur un pilote (risque de dependance applicative)."
        }
    }
}

if ($Scope -in 'All','Update')  { Write-Log "--- Mises a jour applicatives ---"; Invoke-Updates }
if ($Scope -in 'All','Windows') { Write-Log "--- Correctifs systeme ---"; Invoke-WindowsUpdate }

Write-Log "=============================================================="
Write-Log " Changements : $script:Changes   Erreurs : $script:Errors"
if ($script:RebootNeeded) {
    Write-Log " REDEMARRAGE REQUIS" 'WARN'
    if ($Apply -and $AllowReboot) { Write-Log " Redemarrage dans 5 minutes"; shutdown.exe /r /t 300 /c "Maintenance OMNITECH" }
}
Write-Log "=============================================================="

if ($script:Errors -gt 0)      { exit 1 }
elseif ($script:RebootNeeded)  { exit 2 }
else                           { exit 0 }
