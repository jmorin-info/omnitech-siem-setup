<#
  Bind-SqlCertificate.ps1
  ============================================================================
  Lie un certificat TLS a l'instance SQL Server (chiffrement valide cote client
  avec trustServerCertificate=false). A lancer EN ADMIN sur le serveur SEAL
  (BX-SEAL-OMEGA). Fait, automatiquement :
    1. Localise le certificat serveur (SAN = FQDN, EKU Server Authentication,
       cle privee presente) dans LocalMachine\My  (ou -Thumbprint impose).
    2. Donne au compte de service SQL le droit de LIRE la cle privee.
    3. Ecrit le thumbprint dans le registre de l'instance (+ ForceEncryption).
    4. (option -RestartSql) redemarre le service SQL pour appliquer.

  PRE-REQUIS : un certificat serveur emis par la PKI OMNITECH doit exister dans
  LocalMachine\My, avec SAN = bx-seal-omega.omnitech.security et EKU
  'Authentification du serveur' (1.3.6.1.5.5.7.3.1). S'il n'existe pas encore,
  l'emettre d'abord (voir bloc "ENROLLMENT" en bas de ce fichier).

  EXEMPLES
    # auto-detection + redemarrage SQL :
    powershell -ExecutionPolicy Bypass -File .\Bind-SqlCertificate.ps1 -RestartSql
    # cert precis :
    .\Bind-SqlCertificate.ps1 -Thumbprint 'AABBCC...' -RestartSql
  ============================================================================
#>
[CmdletBinding()]
param(
  [string]$Fqdn        = "bx-seal-omega.omnitech.security",
  [string]$InstanceSvc = "MSSQLSERVER",     # service de l'instance par defaut
  [string]$Thumbprint,
  [switch]$RestartSql
)
$ErrorActionPreference = "Stop"

# --- 1. Instance SQL + compte de service ---
$map = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction Stop
$instId = $map.$InstanceSvc          # ex. MSSQL15.MSSQLSERVER
if (-not $instId) { throw "Instance '$InstanceSvc' introuvable (Instance Names\SQL)." }
$regBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instId\MSSQLServer\SuperSocketNetLib"
$svc = Get-CimInstance Win32_Service -Filter "Name='$InstanceSvc'"
$svcAccount = $svc.StartName
if (-not $svcAccount) { throw "Compte de service SQL introuvable." }
Write-Host "Instance : $instId   Service : $InstanceSvc   Compte : $svcAccount" -ForegroundColor Cyan

# --- 2. Certificat ---
if ($Thumbprint) {
  $cert = Get-Item ("Cert:\LocalMachine\My\" + ($Thumbprint -replace '\s','')) -ErrorAction Stop
} else {
  $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.HasPrivateKey -and
    ($_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1') -and
    ( ($_.DnsNameList.Unicode -contains $Fqdn) -or ($_.Subject -match [regex]::Escape($Fqdn)) )
  } | Sort-Object NotAfter -Descending | Select-Object -First 1
}
if (-not $cert) {
  throw "Aucun certificat serveur pour '$Fqdn' (SAN + Server Authentication + cle privee) dans LocalMachine\My. Emettre d'abord un certificat PKI OMNITECH (voir bloc ENROLLMENT en bas du script), puis relancer."
}
Write-Host "Certificat : $($cert.Subject)  TP=$($cert.Thumbprint)  exp=$($cert.NotAfter)" -ForegroundColor Green

# --- 3. Droit de lecture sur la cle privee pour le compte SQL ---
try {
  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
  $keyName = $rsa.Key.UniqueName        # CNG
  $paths = @(
    (Join-Path $env:ProgramData "Microsoft\Crypto\Keys\$keyName"),                # CNG machine
    (Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$keyName")       # CAPI machine
  )
  $keyFile = $paths | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($keyFile) {
    $acl  = Get-Acl $keyFile
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($svcAccount, "Read", "Allow")
    $acl.AddAccessRule($rule); Set-Acl -Path $keyFile -AclObject $acl
    Write-Host "Droit de lecture accorde a '$svcAccount' sur la cle privee." -ForegroundColor Green
  } else {
    Write-Warning "Fichier de cle privee introuvable automatiquement. Accorder manuellement au compte SQL le droit de lire la cle (certlm.msc -> cert -> Toutes les taches -> Gerer les cles privees)."
  }
} catch {
  Write-Warning "ACL cle privee non appliquee automatiquement : $($_.Exception.Message). Faire via certlm.msc (Gerer les cles privees)."
}

# --- 4. Registre : thumbprint + ForceEncryption ---
Set-ItemProperty -Path $regBase -Name "Certificate" -Value ($cert.Thumbprint.ToLower())
Set-ItemProperty -Path $regBase -Name "ForceEncryption" -Value 1 -Type DWord
Write-Host "Registre mis a jour (Certificate + ForceEncryption=1) sur $instId." -ForegroundColor Green

# --- 5. Redemarrage ---
if ($RestartSql) {
  Write-Host "Redemarrage de $InstanceSvc ..." -ForegroundColor Yellow
  Restart-Service -Name $InstanceSvc -Force
  Write-Host "SQL redemarre. TLS stricte active." -ForegroundColor Green
} else {
  Write-Host "`nPour appliquer : Restart-Service -Name $InstanceSvc -Force" -ForegroundColor Yellow
}
Write-Host "`nEnsuite, cote SIEM, on (re)deploie seal-omega.conf : la validation stricte du certificat fonctionnera." -ForegroundColor Cyan

<#
============================================================================
  ENROLLMENT — si aucun certificat serveur n'existe encore sur ce serveur
  --------------------------------------------------------------------------
  Emettre un certificat depuis la PKI interne OMNITECH avec SAN = le FQDN et
  l'EKU 'Server Authentication'. Exemple avec certreq + un modele AD CS
  (adapter le nom du modele/CA a votre PKI) :

  1) Fichier request.inf :
     [Version]
     Signature="$Windows NT$"
     [NewRequest]
     Subject = "CN=bx-seal-omega.omnitech.security"
     KeyLength = 2048
     MachineKeySet = TRUE
     Exportable = FALSE
     KeySpec = 1
     KeyUsage = 0xA0
     ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
     RequestType = PKCS10
     [EnhancedKeyUsageExtension]
     OID = 1.3.6.1.5.5.7.3.1     ; Server Authentication
     [Extensions]
     2.5.29.17 = "{text}"
     _continue_ = "dns=bx-seal-omega.omnitech.security"

  2) Demander + recuperer + installer (CertificateTemplate = votre modele) :
     certreq -new request.inf request.req
     certreq -submit -attrib "CertificateTemplate:WebServerOMNITECH" request.req cert.cer
     certreq -accept cert.cer

  3) Relancer ce script (Bind-SqlCertificate.ps1 -RestartSql).
============================================================================
#>
