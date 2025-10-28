# PowerShell Script: make_root_and_int.ps1
$ErrorActionPreference = "Stop"

# -------------------------
# Create base directories for Root CA
# -------------------------
New-Item -ItemType Directory -Force -Path demoCA\root\certs | Out-Null
New-Item -ItemType Directory -Force -Path demoCA\root\crl | Out-Null
New-Item -ItemType Directory -Force -Path demoCA\root\newcerts | Out-Null
New-Item -ItemType Directory -Force -Path demoCA\root\private | Out-Null

# Create index.txt and serial for Root CA
if (-not (Test-Path "demoCA\root\index.txt")) {
    New-Item -ItemType File -Path demoCA\root\index.txt | Out-Null
}
Set-Content -Path demoCA\root\serial -Value "1000"

# -------------------------
# Generate Root CA
# -------------------------
Write-Host "[*] Generating Root CA..."
openssl genrsa -out demoCA\root\private\ca.key.pem 4096
openssl req -x509 -new -nodes -key demoCA\root\private\ca.key.pem -sha256 -days 3650 `
  -subj "/C=IN/ST=Bihar/O=DemoServices/CN=DemoRootCA" `
  -out demoCA\root\ca.cert.pem

# -------------------------
# Create base directories for Intermediate CA
# -------------------------
New-Item -ItemType Directory -Force -Path demoCA\intermediate\certs | Out-Null
New-Item -ItemType Directory -Force -Path demoCA\intermediate\crl | Out-Null
New-Item -ItemType Directory -Force -Path demoCA\intermediate\newcerts | Out-Null
New-Item -ItemType Directory -Force -Path demoCA\intermediate\private | Out-Null

# Create index.txt and serial for Intermediate CA
if (-not (Test-Path "demoCA\intermediate\index.txt")) {
    New-Item -ItemType File -Path demoCA\intermediate\index.txt | Out-Null
}
Set-Content -Path demoCA\intermediate\serial -Value "1000"

# -------------------------
# Generate Intermediate CA
# -------------------------
Write-Host "[*] Generating Intermediate CA..."
openssl genrsa -out demoCA\intermediate\private\int.key.pem 4096
openssl req -new -key demoCA\intermediate\private\int.key.pem `
  -subj "/C=IN/ST=Bihar/O=DemoServices/OU=Intermediate/CN=DemoIntermediateCA" `
  -out demoCA\intermediate\int.csr.pem

# -------------------------
# Sign Intermediate CA with Root
# -------------------------
Write-Host "[*] Signing Intermediate CA with Root..."
openssl ca -config openssl.cnf `
  -extensions v3_intermediate_ca `
  -days 1825 -notext -md sha256 `
  -in demoCA\intermediate\int.csr.pem `
  -out demoCA\intermediate\int.cert.pem `
  -batch

# -------------------------
# Create chain files
# -------------------------
Copy-Item demoCA\intermediate\int.cert.pem demoCA\intermediate\ca-chain.pem -Force
Get-Content demoCA\intermediate\int.cert.pem, demoCA\root\ca.cert.pem | `
    Set-Content demoCA\intermediate\chain.pem

Write-Host "`n[+] Root and Intermediate CA generation complete!"
