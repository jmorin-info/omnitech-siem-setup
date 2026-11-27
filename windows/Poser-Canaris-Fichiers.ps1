<#
.SYNOPSIS
  SIEM v5 chantier 1 (27/11/2026) - Fichiers canaris sur les partages d'un serveur de fichiers. Simulation par défaut.
.DESCRIPTION
  Pose des fichiers appâts (mêmes noms que fichiers_canaris dans site.json, lus par la règle Graylog
  omni-v5-ad-canari-fichier) dans des dossiers de partage, avec une SACL d'audit « Tout le monde : Lecture des
  données (réussite) » -> événement 4663 sur le serveur de fichiers.
  Prérequis : sous-catégorie « Système de fichiers » (réussite) active sur le serveur cible.
  Aucune modification des droits d'accès (DACL héritée du dossier), aucun impact RDP/SMB/FTP.
  Après la pose : vérifier un 4663 dans Graylog (ouverture test par un compte d'administration), puis activer la
  définition « OMNI v5 - AD Fichier canari ouvert » : PUT /events/definitions/<id>/schedule.
  Exclusions déjà dans la règle : SYSTEM (antivirus, DFS-R, indexation, VSS) et comptes machine.
  ATTENTION DFS-R : un canari posé dans un dossier répliqué l'est aussi sur les autres membres du groupe de réplication.
  Les noms réels des canaris ne doivent jamais être publiés : les passer par -Noms (valeurs ci-dessous = exemples).
.PARAMETER Dossiers  Chemins locaux (sur le serveur de fichiers) ou UNC des dossiers où poser un canari.
.PARAMETER Noms      Noms des fichiers canaris (identiques à fichiers_canaris de site.json).
.EXAMPLE
  .\Poser-Canaris-Fichiers.ps1 -Dossiers '\\SRV-FICHIERS\Compta$\Archives','\\SRV-FICHIERS\Direction$' -Noms 'Nom 1.xlsx','Nom 2.kdbx'   # simulation
  .\Poser-Canaris-Fichiers.ps1 -Dossiers ... -Noms ... -Appliquer
  .\Poser-Canaris-Fichiers.ps1 -Dossiers ... -Noms ... -Retour
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string[]]$Dossiers,
  [string[]]$Noms = @('Exemple - canari 1.xlsx', 'Exemple - canari 2.kdbx'),
  [switch]$Appliquer,
  [switch]$Retour,
  [string]$Journal = 'C:\DC\Logs\Canaris-Fichiers-SIEM-v5.log'
)
$ErrorActionPreference = 'Stop'
$Contenu = "Document archive. Ne pas modifier. (OMNITECH)"
function Write-Journal([string]$m) { $l = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m"; Write-Output $l; if ($Appliquer -or $Retour) { Add-Content -Path $Journal -Value $l -Encoding UTF8 } }
$mode = if ($Retour) { 'RETOUR' } elseif ($Appliquer) { 'APPLIQUER' } else { 'SIMULATION' }
Write-Journal "=== Canaris fichiers SIEM v5 - mode $mode"
$i = 0
foreach ($d in $Dossiers) {
  $nom = $Noms[$i % $Noms.Count]; $i++
  $f = Join-Path $d $nom
  if ($Retour) {
    if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force; Write-Journal "supprime : $f" } else { Write-Journal "absent : $f" }
    continue
  }
  if (-not (Test-Path -LiteralPath $d)) { Write-Journal "IGNORE (dossier introuvable) : $d"; continue }
  if (Test-Path -LiteralPath $f) { Write-Journal "deja present : $f"; continue }
  if (-not $Appliquer) { Write-Journal "[simulation] poserait $f + SACL Tout le monde/ReadData/Success"; continue }
  Set-Content -LiteralPath $f -Value $Contenu -Encoding UTF8
  (Get-Item -LiteralPath $f).LastWriteTime = (Get-Date).AddMonths(-7)
  $acl = Get-Acl -LiteralPath $f -Audit
  $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
  $regle = [System.Security.AccessControl.FileSystemAuditRule]::new([System.Security.Principal.IdentityReference]$everyone, [System.Security.AccessControl.FileSystemRights]'ReadData', [System.Security.AccessControl.InheritanceFlags]'None', [System.Security.AccessControl.PropagationFlags]'None', [System.Security.AccessControl.AuditFlags]'Success')
  $acl.AddAuditRule($regle)
  Set-Acl -LiteralPath $f -AclObject $acl
  Write-Journal "pose : $f (SACL lecture)"
}
Write-Journal "=== fin ($mode)"
