param(
    [string]$CN,
    [string]$ROLE,
    [string]$TYPE = "client"
)

if (-not $CN -or -not $ROLE) {
    Write-Host "Usage: .\issue_cert.ps1 <common_name> <role> [client|server]"
    exit 1
}

$EXTFILE = "roles_ext.cnf"
@"
[ req_ext ]
subjectAltName = DNS:$CN
1.2.3.4.5.6.7.8.1 = ASN1:UTF8String:role=$ROLE
"@ | Set-Content -Path $EXTFILE -Encoding ascii

# Generate key + CSR
& openssl genrsa -out "$CN.key.pem" 2048
& openssl req -new -key "$CN.key.pem" -subj "/C=IN/O=DemoServices/OU=Backend/CN=$CN" -out "$CN.csr.pem"

# Sign using intermediate CA
if ($TYPE -eq "server") {
    & openssl x509 -req -in "$CN.csr.pem" `
        -CA "C:\Users\2003v\Desktop\Demo\PKI-RBAC-DEMO\openssl\demoCA\intermediate\int.cert.pem" `
        -CAkey "C:\Users\2003v\Desktop\Demo\PKI-RBAC-DEMO\openssl\demoCA\intermediate\int.key.pem" `
        -CAcreateserial -out "$CN.cert.pem" -days 365 -sha256 `
        -extfile $EXTFILE -extensions req_ext
}
else {
    & openssl x509 -req -in "$CN.csr.pem" `
        -CA "C:\Users\2003v\Desktop\Demo\PKI-RBAC-DEMO\openssl\demoCA\intermediate\int.cert.pem" `
        -CAkey "C:\Users\2003v\Desktop\Demo\PKI-RBAC-DEMO\openssl\demoCA\intermediate\int.key.pem" `
        -CAcreateserial -out "$CN.cert.pem" -days 365 -sha256 `
        -extfile $EXTFILE -extensions req_ext
}

Write-Host "Issued $TYPE cert: $CN.cert.pem (role=$ROLE)"
