param(
    [string]$CN,
    [string]$ROLE,
    [string]$TYPE = "client",
    [string]$OUTDIR = "."   # default current folder
)

if (-not $CN -or -not $ROLE) {
    Write-Host "Usage: .\issue_cert.ps1 <common_name> <role> [client|server] <outdir>"
    exit 1
}

# Make sure OUTDIR exists
if (!(Test-Path $OUTDIR)) {
    New-Item -ItemType Directory -Path $OUTDIR | Out-Null
}

$EXTFILE = Join-Path $OUTDIR "roles_ext.cnf"

@"
[ req_ext ]
subjectAltName = DNS:$CN
1.2.3.4.5.6.7.8.1 = ASN1:UTF8String:role=$ROLE
"@ | Set-Content -Path $EXTFILE -Encoding ascii

# File paths inside OUTDIR
$keyFile  = Join-Path $OUTDIR "$CN.key.pem"
$csrFile  = Join-Path $OUTDIR "$CN.csr.pem"
$certFile = Join-Path $OUTDIR "$CN.cert.pem"

# Generate key + CSR
& openssl genrsa -out $keyFile 2048
& openssl req -new -key $keyFile -subj "/C=IN/O=DemoServices/OU=Backend/CN=$CN" -out $csrFile

# Sign using intermediate CA
& openssl x509 -req -in $csrFile `
    -CA "C:\Users\2003v\Desktop\Demo\PKI-RBAC-DEMO\openssl\demoCA\intermediate\int.cert.pem" `
    -CAkey "C:\Users\2003v\Desktop\Demo\PKI-RBAC-DEMO\openssl\demoCA\intermediate\int.key.pem" `
    -CAcreateserial -out $certFile -days 365 -sha256 `
    -extfile $EXTFILE -extensions req_ext

Write-Host "Issued $TYPE cert: $certFile (role=$ROLE)"
