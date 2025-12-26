param(
    [string]$CN,
    [string]$ROLE,
    [string]$TYPE = "client",
    [string]$OUTDIR = "."
)

if (-not $CN -or -not $ROLE) {
    Write-Host "Usage: .\issue_cert.ps1 -CN <common_name> -ROLE <role> [-TYPE client|server] [-OUTDIR path]"
    exit 1
}

# Ensure OUTDIR exists
if (!(Test-Path $OUTDIR)) {
    New-Item -ItemType Directory -Path $OUTDIR | Out-Null
}

$EXTFILE = Join-Path $OUTDIR "roles_ext.cnf"

@"
[ req_ext ]
subjectAltName = DNS:$CN
1.2.3.4.5.6.7.8.1 = ASN1:UTF8String:$ROLE
"@ | Set-Content -Path $EXTFILE -Encoding ascii

$keyFile  = Join-Path $OUTDIR "$CN.key.pem"
$csrFile  = Join-Path $OUTDIR "$CN.csr.pem"
$certFile = Join-Path $OUTDIR "$CN.cert.pem"

# Generate key + CSR
& openssl genrsa -out $keyFile 2048
& openssl req -new -key $keyFile -subj "/C=IN/O=DemoServices/OU=Backend/CN=$CN" -out $csrFile

# Sign using Intermediate CA
& openssl x509 -req -in $csrFile `
    -CA "C:\Users\2003v\Desktop\Demo\PKI-RBAC-DEMO\openssl\demoCA\intermediate\int.cert.pem" `
    -CAkey "C:\Users\2003v\Desktop\Demo\PKI-RBAC-DEMO\openssl\demoCA\intermediate\private\int.key.pem" `
    -CAcreateserial -out $certFile -days 365 -sha256 `
    -extfile $EXTFILE -extensions req_ext


Write-Host "✅ Issued $TYPE cert for $CN with embedded role: $ROLE"
