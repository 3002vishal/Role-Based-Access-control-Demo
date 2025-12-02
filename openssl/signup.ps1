# =========================================================
#  CLIENT SIGNUP (HSM ENROLLMENT - SafeSign/Moserbear)
# =========================================================

$serverUrl = "http://localhost:5000"

# 1. INPUTS
$username = Read-Host "Enter Username (e.g., vishalku)"
$role     = Read-Host "Enter Role (admin/editor/viewer)"

# --- FILE NAMES ---
$infFileName = "$username.inf"
$csrFileName = "$username.req"
$responseFileName = "$username.cer"

Write-Host "`n[CLIENT] 1. Creating INF configuration for HSM..." -ForegroundColor Cyan

# 2. GENERATE THE .INF CONTENT using the user's specific settings
# Note: The Subject MUST match the CN you want in the certificate
$infContent = @"
[NewRequest]
Subject = "CN=$username, O=MyCompany, C=IN"
KeyLength = 2048
KeySpec = 2 ; Signature Only - CRITICAL for SafeSign/Moserbear
KeyUsage = 0xA0 ; Digital Signature, Key Encipherment
MachineKeySet = FALSE
Exportable = FALSE ; Private Key stays on HSM
RequestType = PKCS10
SMIME = FALSE

; Provider configured for SafeSign/Moserbear
ProviderName = "SafeSign Standard Cryptographic Service Provider"
ProviderType = 1

; Force a specific container based on the username
KeyContainer = "$username"

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2 ; Client Authentication
"@

# Save INF to disk
$infContent | Out-File -FilePath $infFileName -Encoding ASCII

Write-Host "   -> INF file created: $infFileName" -ForegroundColor Gray

# 3. GENERATE KEYS & CSR (Runs the certreq tool)
Write-Host "`n[CLIENT] 2. Generating Keys & CSR (certreq)..." -ForegroundColor Cyan

# This command prompts the user for the HSM PIN if needed and generates the private key.
certreq -new -q $infFileName $csrFileName

if (-not (Test-Path $csrFileName)) {
    Write-Error "Failed to generate CSR. Check if your token is inserted and PIN is correct."
    exit
}

# --- CRITICAL FIX HERE ---
# Old Line: $csrContent = Get-Content $csrFileName -Raw
# New Line: Uses .NET to ensure it reads as a pure single string, preventing JSON errors on Node.js
$csrContent = [System.IO.File]::ReadAllText("$PWD\$csrFileName")

Write-Host "   -> CSR Generated successfully." -ForegroundColor Green

# 4. SEND TO BACKEND
Write-Host "`n[CLIENT] 3. Sending CSR to Enrollment Server..." -ForegroundColor Cyan

$payload = @{
    username = $username 
    csr      = $csrContent
    role     = $role
} | ConvertTo-Json

try {
    # Calls the /api/enroll endpoint in Node.js
    $response = Invoke-RestMethod -Uri "$serverUrl/api/enroll" -Method Post -Body $payload -ContentType "application/json"

    if ($response.success) {
        Write-Host "   -> Server Signed the Certificate!" -ForegroundColor Green

        # 5. SAVE RESPONSE TO FILE
        $certContent = $response.certificate
        $certContent | Out-File -FilePath $responseFileName -Encoding ASCII

        # 6. INSTALL & BIND (Accept the response)
        Write-Host "`n[CLIENT] 4. Binding Certificate to Private Key in Store..." -ForegroundColor Cyan
        
        # 'certreq -accept' binds the public certificate to the private key on the HSM/Store.
        certreq -accept -q $responseFileName

        Write-Host "   -> SUCCESS! Certificate is installed and ready for login." -ForegroundColor Yellow
        
        # Cleanup temporary files
        Remove-Item $infFileName, $csrFileName, $responseFileName -ErrorAction SilentlyContinue
    }
    else {
        Write-Error "Server Error: $($response.error)"
    }
}
catch {
    Write-Error "API Connection Failed or Server Error: $_"
}