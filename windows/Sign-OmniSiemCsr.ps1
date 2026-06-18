<#
.SYNOPSIS
  Sign-OmniSiemCsr.ps1 - Signe le CSR du SIEM via l'AC AD CS (template WebServer).

.DESCRIPTION
  Complement Windows du renouvellement automatique du certificat du SIEM
  (cf. /usr/local/sbin/omni-cert-renew cote Linux). Workflow :
    1. le SIEM depose un CSR sur le partage :  <Share>\SIEM\certs\graylog.csr
    2. CE script (planifie) le detecte, le soumet a l'AC avec le template
       WebServer (Server Authentication + SAN), et redepose le certificat
       signe :  <Share>\SIEM\certs\graylog-signed.crt
    3. le SIEM l'installe automatiquement et recharge nginx.

  La cle privee ne quitte JAMAIS le SIEM ; seuls le CSR et le certificat
  (tous deux publics) transitent.

.PARAMETER CertDir
  Dossier d'echange (le partage). Defaut : \\10.33.50.5\Public\SIEM\certs

.PARAMETER Template
  Modele de certificat AD CS. Defaut : WebServer (doit avoir Server
  Authentication ; le compte executant doit avoir le droit Enroll dessus).

.NOTES
  Ou l'executer : un serveur Windows membre du domaine ayant acces a l'AC et
  au partage — IDEALEMENT la PKI elle-meme (10.33.50.248, l'AC est locale) ou
  le serveur de fichiers (10.33.50.5). Aucun flux pare-feu nouveau dans ce cas.
  Tache planifiee : toutes les 15-30 min, compte de service avec droit Enroll
  sur le template WebServer. Executer en tant que ce compte.
#>
[CmdletBinding()]
param(
  [string]$CertDir  = "\\10.33.50.5\Public\SIEM\certs",
  [string]$Template = "OMS-WebServer"
)
$ErrorActionPreference = "Stop"
$csr    = Join-Path $CertDir "graylog.csr"
$signed = Join-Path $CertDir "graylog-signed.crt"
$tmpCer = Join-Path $env:TEMP "graylog-signed.cer"

if (-not (Test-Path $csr)) { Write-Host "[=] Aucun CSR en attente ($csr)"; return }
Write-Host "[*] CSR detecte -> soumission a l'AC (template $Template)"

# Soumission a l'autorite de certification. -submit choisit l'AC du domaine ;
# l'attribut force le template. Le resultat est un .cer (base64 X.509).
Remove-Item $tmpCer -ErrorAction SilentlyContinue
$out = certreq -submit -attrib "CertificateTemplate:$Template" $csr $tmpCer 2>&1
if (-not (Test-Path $tmpCer)) {
  Write-Host "[!] Echec de la signature :`n$out"
  throw "certreq -submit n'a pas produit de certificat (droits Enroll sur '$Template' ? AC joignable ?)"
}

# S'assurer d'un format PEM (BEGIN CERTIFICATE) pour nginx
$raw = Get-Content $tmpCer -Raw
if ($raw -notmatch "BEGIN CERTIFICATE") {
  # convertir DER -> base64 si besoin
  certutil -encode $tmpCer "$tmpCer.pem" | Out-Null
  $raw = Get-Content "$tmpCer.pem" -Raw
  Remove-Item "$tmpCer.pem" -ErrorAction SilentlyContinue
}

# Depose atomique : ecrire un .tmp puis renommer (le SIEM ne lit jamais un fichier partiel)
$tmpOut = "$signed.tmp"
Set-Content -Path $tmpOut -Value $raw -Encoding Ascii
Move-Item -Force $tmpOut $signed
Remove-Item $tmpCer -ErrorAction SilentlyContinue
# le CSR est consomme : le retirer pour eviter une re-signature
Remove-Item $csr -ErrorAction SilentlyContinue

Write-Host "[+] Certificat signe depose : $signed"
Write-Host "    Le SIEM l'installera a son prochain passage (timer quotidien)."
