param(
    [Parameter(Mandatory=$true)] [string]$username,
    # REPLACED: Single $role with a JSON string containing all service roles
    [Parameter(Mandatory=$true)] [string]$serviceRoles, 
    [Parameter(Mandatory=$true)] [string]$email,
    [Parameter(Mandatory=$true)] [string]$orgUnit,
    [Parameter(Mandatory=$true)] [string]$org,
    [Parameter(Mandatory=$true)] [string]$state,
    [Parameter(Mandatory=$true)] [string]$country
)

# Configuration
$serverUrl = "http://localhost:5000"
$infFileName = "$username.inf"
$csrFileName = "$username.req"
$responseFileName = "$username.cer"

# Helper to output JSON
function Output-Json($status, $msg, $data = $null) {
    $obj = @{
        status = $status
        message = $msg
        data = $data
    }
    Write-Output ($obj | ConvertTo-Json -Compress)
}

try {
    # 0. VALIDATE JSON INPUT
    # We verify that the passed serviceRoles string is actually valid JSON before proceeding
    try {
        $testJson = $serviceRoles | ConvertFrom-Json
    } catch {
        throw "The parameter -serviceRoles must be a valid JSON string. Error: $($_.Exception.Message)"
    }

    Write-Host "[CLIENT] 1. Creating INF configuration for $username..." -ForegroundColor Cyan

    # 1. GENERATE THE .INF CONTENT
    # Note: We do NOT put the roles here. We send them to the server separately.
    $infContent = @"
[NewRequest]
Subject = "CN=$username, E=$email, OU=$orgUnit, O=$org, S=$state, C=$country"
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

    # 2. GENERATE KEYS & CSR
    Write-Host "[CLIENT] 2. Generating Keys & CSR..." -ForegroundColor Cyan
    certreq -new -q $infFileName $csrFileName

    if (-not (Test-Path $csrFileName)) { throw "Failed to generate CSR." }

    $csrContent = [System.IO.File]::ReadAllText("$PWD\\$csrFileName")

    # 3. SEND TO BACKEND API
    Write-Host "[CLIENT] 3. Sending CSR and Role Data to Backend..." -ForegroundColor Cyan

    # UPDATED PAYLOAD: We send the serviceRoles JSON string to the backend
    $payload = @{
        username     = $username
        csr          = $csrContent
        serviceRoles = $serviceRoles  # Sending the JSON string directly
        email        = $email
    } | ConvertTo-Json -Depth 10

    $response = Invoke-RestMethod -Uri "$serverUrl/api/enroll" -Method Post -Body $payload -ContentType "application/json"

    if ($response.success) {
        Write-Host "[CLIENT] Server Signed the Certificate with Roles!" -ForegroundColor Green

        # 4. SAVE & INSTALL
        $certContent = $response.certificate
        $certContent | Out-File -FilePath $responseFileName -Encoding ASCII

        Write-Host "[CLIENT] 4. Binding Certificate to Token..." -ForegroundColor Cyan
        certreq -accept -q $responseFileName

        Remove-Item $infFileName, $csrFileName, $responseFileName -ErrorAction SilentlyContinue
        Output-Json "success" "Certificate installed successfully" $certContent
    }
    else {
        throw "Server Error: $($response.error)"
    }
}
catch {
    $errorMsg = $_.Exception.Message
    Write-Host "ERROR: $errorMsg" -ForegroundColor Red
    Output-Json "error" $errorMsg
    exit 1
}