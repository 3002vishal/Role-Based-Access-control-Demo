# PowerShell Script: make_root_and_int.ps1
# Stop on error
$ErrorActionPreference = "Stop"

# -------------------------
# Create base directories
# -------------------------
New-Item -ItemType Directory -Force -Path demoCA\root | Out-Null
New-Item -ItemType Directory -Force -Path demoCA\intermediate | Out-Null

# -------------------------
# Root CA
# -------------------------
Write-Host "[*] Generating Root CA..."
openssl genrsa -out demoCA\root\ca.key.pem 4096
openssl req -x509 -new -nodes -key demoCA\root\ca.key.pem -sha256 -days 3650 `
  -subj "/C=IN/ST=Bihar/O=DemoServices/CN=DemoRootCA" `
  -out demoCA\root\ca.cert.pem

# -------------------------
# Intermediate CA
# -------------------------
Write-Host "[*] Generating Intermediate CA..."
openssl genrsa -out demoCA\intermediate\int.key.pem 4096
openssl req -new -key demoCA\intermediate\int.key.pem `
  -subj "/C=IN/ST=Bihar/O=DemoServices/OU=Intermediate/CN=DemoIntermediateCA" `
  -out demoCA\intermediate\int.csr.pem

# Sign intermediate with root
openssl x509 -req -in demoCA\intermediate\int.csr.pem `
  -CA demoCA\root\ca.cert.pem -CAkey demoCA\root\ca.key.pem `
  -CAcreateserial -out demoCA\intermediate\int.cert.pem -days 1825 -sha256

# -------------------------
# Create intermediate CA DB structure
# -------------------------
New-Item -ItemType Directory -Force -Path demoCA\intermediate\certs | Out-Null
New-Item -ItemType Directory -Force -Path demoCA\intermediate\crl | Out-Null
New-Item -ItemType Directory -Force -Path demoCA\intermediate\newcerts | Out-Null
New-Item -ItemType Directory -Force -Path demoCA\intermediate\private | Out-Null

# Create index.txt and serial if not exist
if (-not (Test-Path "demoCA\intermediate\index.txt")) {
    New-Item -ItemType File -Path demoCA\intermediate\index.txt | Out-Null
}
Set-Content -Path demoCA\intermediate\serial -Value "1000"

# -------------------------
# Create chain files
# -------------------------
Copy-Item demoCA\intermediate\int.cert.pem demoCA\intermediate\ca-chain.pem -Force
Get-Content demoCA\intermediate\int.cert.pem, demoCA\root\ca.cert.pem | `
    Set-Content demoCA\intermediate\chain.pem

# -------------------------
# Success message
# -------------------------

