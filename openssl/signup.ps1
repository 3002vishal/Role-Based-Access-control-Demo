# File: signup.ps1

# 1. ACCEPT PARAMETERS FROM BRIDGE
param(
    [Parameter(Mandatory=$true)]
    [string]$username,

    [Parameter(Mandatory=$true)]
    [string]$role
)

# Configuration
$serverUrl = "http://localhost:5000"
$infFileName = "$username.inf"
$csrFileName = "$username.req"
$responseFileName = "$username.cer"

# Helper to output JSON for the Node.js bridge
function Output-Json($status, $msg, $data = $null) {
    $obj = @{
        status = $status
        message = $msg
        data = $data
    }
    Write-Output ($obj | ConvertTo-Json -Compress)
}

try {
    Write-Host "[CLIENT] 1. Creating INF configuration for $username..." -ForegroundColor Cyan

    # 2. GENERATE THE .INF CONTENT
    $infContent = @"
[NewRequest]
Subject = "CN=$username, O=MyCompany, C=IN"
KeyLength = 2048
KeySpec = 2 
KeyUsage = 0xA0 
MachineKeySet = FALSE
Exportable = FALSE 
RequestType = PKCS10
SMIME = FALSE
ProviderName = "SafeSign Standard Cryptographic Service Provider"
ProviderType = 1
KeyContainer = "$username"
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2 
"@

    $infContent | Out-File -FilePath $infFileName -Encoding ASCII

    # 3. GENERATE KEYS & CSR
    Write-Host "[CLIENT] 2. Generating Keys & CSR..." -ForegroundColor Cyan
    
    # Run certreq (This triggers the PIN Popup)
    certreq -new -q $infFileName $csrFileName

    if (-not (Test-Path $csrFileName)) {
        throw "Failed to generate CSR. Check token/PIN."
    }

    # Read CSR safely
    $csrContent = [System.IO.File]::ReadAllText("$PWD\$csrFileName")

    # 4. SEND TO BACKEND API
    Write-Host "[CLIENT] 3. Sending CSR to Backend..." -ForegroundColor Cyan

    $payload = @{
        username = $username
        csr      = $csrContent
        role     = $role
    } | ConvertTo-Json -Depth 10

    $response = Invoke-RestMethod -Uri "$serverUrl/api/enroll" -Method Post -Body $payload -ContentType "application/json"

    if ($response.success) {
        Write-Host "[CLIENT] Server Signed the Certificate!" -ForegroundColor Green

        # 5. SAVE & INSTALL
        $certContent = $response.certificate
        $certContent | Out-File -FilePath $responseFileName -Encoding ASCII

        Write-Host "[CLIENT] 4. Binding Certificate to Token..." -ForegroundColor Cyan
        certreq -accept -q $responseFileName

        # Cleanup
        Remove-Item $infFileName, $csrFileName, $responseFileName -ErrorAction SilentlyContinue

        # SUCCESS: Output JSON for Bridge.js
        Output-Json "success" "Certificate installed successfully" $certContent
    }
    else {
        throw "Server Error: $($response.error)"
    }
}
catch {
    # FAIL: Output JSON for Bridge.js
    $errorMsg = $_.Exception.Message
    Write-Host "ERROR: $errorMsg" -ForegroundColor Red
    Output-Json "error" $errorMsg
    exit 1
}