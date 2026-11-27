<#
.SYNOPSIS
  SIEM v5 chantier 1 (27/11/2026) - Audit AD CS complet (modèles + configuration CA). Appliqué le 27/11/2026 (décision jmorin).
.DESCRIPTION
  Constat 30 j : seuls 4886/4887/4888/4870 arrivent de BX-PKI2022 ; aucun 4882/4885/4890/4892/4899/4900 et aucun 5136 sur
  les modèles (pas de SACL sur CN=Public Key Services). La règle omni-v5-ad-adcs-modele-ca est prête et attend ces sources.
  Étapes (sur BX-PKI2022, en adm-jmorin) :
   1. CA\AuditFilter = 127 (toutes catégories : config, sécurité, demandes, révocations, sauvegarde/restauration de la CA).
   2. policy\EditFlags += EDITF_AUDITCERTTEMPLATELOAD (0x200000) -> 4898/4899/4900 au chargement/modif de modèle.
   3. Redémarrage de certsvc (coupure de quelques secondes de l'émission de certificats) - À PLANIFIER.
   4. SACL « Tout le monde : Écrire toutes les propriétés / Modifier les autorisations (réussite) » sur
      CN=Public Key Services,CN=Services,CN=Configuration (héritée) -> 5136 côté DC (sous-catégorie « Modification du service d'annuaire » déjà active).
  Volume attendu : très faible (quelques événements par mois, plus 4898 au démarrage de certsvc).
  -Retour remet les valeurs sauvegardées dans C:\DC\Sauvegardes\ADCS\audit-avant-*.json et retire la SACL ajoutée.
#>
[CmdletBinding()]
param([switch]$Appliquer, [switch]$Retour, [string]$CA = 'BX-PKI2022.omnitech.security\Root CA OMNITECH SECURITY')
$ErrorActionPreference = 'Stop'
$sauvDir = 'C:\DC\Sauvegardes\ADCS'; New-Item -ItemType Directory -Force $sauvDir | Out-Null
$confDN = (Get-ADRootDSE).configurationNamingContext
$pks = "AD:\CN=Public Key Services,CN=Services,$confDN"
# Sortie certutil : « EditFlags REG_DWORD = 1014e (65870) » -> on lit la valeur décimale entre parenthèses (27/11 : AuditFilter = 7f (127) déjà).
function Get-Reg([string]$n) {
  $o = certutil -config $CA -getreg $n 2>&1 | Out-String
  if ($o -match 'REG_DWORD = [0-9a-fA-F]+ \((\d+)\)') { [int64]$Matches[1] } elseif ($o -match 'REG_DWORD = (\d+)\s') { [int64]$Matches[1] } else { throw "lecture $n impossible" }
}
$etat = [ordered]@{ AuditFilter = Get-Reg 'CA\AuditFilter'; EditFlags = Get-Reg 'policy\EditFlags'; Date = (Get-Date -Format s) }
Write-Output "Etat actuel : AuditFilter=$($etat.AuditFilter) EditFlags=$($etat.EditFlags)"
$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$regle = [System.DirectoryServices.ActiveDirectoryAuditRule]::new([System.Security.Principal.IdentityReference]$everyone, [System.DirectoryServices.ActiveDirectoryRights]'WriteProperty, WriteDacl, WriteOwner, CreateChild, DeleteChild', [System.Security.AccessControl.AuditFlags]'Success', [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All')
if ($Retour) {
  $f = Get-ChildItem $sauvDir -Filter 'audit-avant-*.json' | Sort-Object LastWriteTime | Select-Object -Last 1
  if (-not $f) { throw 'aucune sauvegarde audit-avant-*.json' }
  $s = Get-Content $f.FullName -Raw | ConvertFrom-Json
  certutil -config $CA -setreg CA\AuditFilter $s.AuditFilter | Out-Null
  certutil -config $CA -setreg policy\EditFlags $s.EditFlags | Out-Null
  $acl = Get-Acl -Path $pks -Audit; [void]$acl.RemoveAuditRule($regle); Set-Acl -Path $pks -AclObject $acl
  Write-Output "Retour applique depuis $($f.Name) ; redemarrer certsvc sur BX-PKI2022 pour prise en compte."
  return
}
if (-not $Appliquer) {
  Write-Output "[simulation] certutil -setreg CA\AuditFilter 127 ; certutil -setreg policy\EditFlags +0x200000 (EDITF_AUDITCERTTEMPLATELOAD) ; SACL sur $pks ; redemarrage certsvc a planifier."
  return
}
$etat | ConvertTo-Json | Set-Content (Join-Path $sauvDir "audit-avant-$(Get-Date -Format yyyyMMdd-HHmm).json") -Encoding UTF8
if ($etat.AuditFilter -ne 127) { certutil -config $CA -setreg CA\AuditFilter 127 | Out-Null }
certutil -config $CA -setreg policy\EditFlags +EDITF_AUDITCERTTEMPLATELOAD | Out-Null
if ((Get-Reg 'policy\EditFlags') -band 0x40000) { throw 'EDITF_ATTRIBUTESUBJECTALTNAME2 present : ARRET (ESC6)' }
$acl = Get-Acl -Path $pks -Audit; $acl.AddAuditRule($regle); Set-Acl -Path $pks -AclObject $acl
Write-Output "Applique. Redemarrer certsvc sur BX-PKI2022 (Restart-Service certsvc) au moment convenu, puis verifier un 4898 dans Graylog."
