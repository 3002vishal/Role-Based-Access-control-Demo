const express = require('express');
const { spawn } = require('child_process');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const os = require('os');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = 3000;

// ==========================================
// 1. POWERSHELL SCRIPTS (Define Logic)
// ==========================================

// --- SCRIPT A: SIGNUP (Enrollment) ---
const SIGNUP_SCRIPT = `
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
`;

// --- SCRIPT B: SIGN (Login) ---
const SIGN_SCRIPT = `
param(
    [string]$ChallengeData
)

Add-Type -AssemblyName System.Security

# 1. Select Certificate
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$store.Open("ReadOnly")
$certs = $store.Certificates.Find("FindByTimeValid", [DateTime]::Now, $false)
$selection = [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection(
    $certs, "Select Token", "Pick your hardware certificate", "SingleSelection"
)

if ($selection.Count -eq 0) { Write-Output "ERROR:User_Cancelled"; exit }
$cert = $selection[0]

# 2. Check Private Key existence
if ($cert.HasPrivateKey -eq $false) {
    Write-Output "ERROR:No_Private_Key_Found"
    exit
}

try {
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($ChallengeData)
    $signatureBytes = $null

    # --- ATTEMPT 1: DIRECT CSP RECONSTRUCTION ---
    try {
        $privKeyInfo = $cert.PrivateKey.CspKeyContainerInfo
        $cspParams = New-Object System.Security.Cryptography.CspParameters
        $cspParams.ProviderName = $privKeyInfo.ProviderName
        $cspParams.ProviderType = 1 
        $cspParams.KeyContainerName = $privKeyInfo.KeyContainerName
        $cspParams.KeyNumber = $privKeyInfo.KeyNumber
        $cspParams.Flags = [System.Security.Cryptography.CspProviderFlags]::UseExistingKey

        $rsaDirect = New-Object System.Security.Cryptography.RSACryptoServiceProvider($cspParams)

        try { $signatureBytes = $rsaDirect.SignData($dataBytes, "SHA256") }
        catch { $signatureBytes = $rsaDirect.SignData($dataBytes, "SHA1") }
    }
    catch { $err1 = $_.Exception.Message }

    # --- ATTEMPT 2: STANDARD LEGACY ---
    if ($null -eq $signatureBytes) {
        try {
            $rsaLegacy = [System.Security.Cryptography.RSACryptoServiceProvider]$cert.PrivateKey
            if ($rsaLegacy) { $signatureBytes = $rsaLegacy.SignData($dataBytes, "SHA256") }
        } catch { $err2 = $_.Exception.Message }
    }

    # --- ATTEMPT 3: MODERN CNG ---
    if ($null -eq $signatureBytes) {
        try {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            if ($rsa) {
                $signatureBytes = $rsa.SignData($dataBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            }
        } catch { $err3 = $_.Exception.Message }
    }

    if ($null -eq $signatureBytes) {
        Write-Output "ERROR:Could_Not_Sign_With_This_Token"
        Write-Output "Details: DirectCSP: $err1 | Legacy: $err2 | CNG: $err3"
        exit 1
    }

    $signatureBase64 = [Convert]::ToBase64String($signatureBytes)
    Write-Output $signatureBase64

} catch {
    Write-Host "ERROR:Critical_Failure"
    Write-Host $_.Exception.Message
    exit 1
}
`;

// ==========================================
// 2. HELPER: WRITE SCRIPT TO TEMP
// ==========================================
function getScriptPath(scriptName) {
    let content = "";
    if (scriptName === 'signup.ps1') content = SIGNUP_SCRIPT;
    else if (scriptName === 'sign.ps1') content = SIGN_SCRIPT;
    else throw new Error("Unknown script requested");

    const tempPath = path.join(os.tmpdir(), `hsm-${scriptName}`);
    try {
        fs.writeFileSync(tempPath, content);
    } catch (e) {
        // Reuse locked file if needed
    }
    return tempPath;
}

// ==========================================
// 3. API ROUTES
// ==========================================

// ROUTE: LOGIN (Signing)
app.post('/sign-challenge', (req, res) => {
    const challenge = req.body.challenge;
    if (!challenge) return res.status(400).json({ error: "No challenge provided" });

    console.log(`[SIGN] Launching Hardware Signer...`);

    try {
        const scriptPath = getScriptPath('sign.ps1');
        const ps = spawn('powershell.exe', [
            '-NoProfile', '-ExecutionPolicy', 'Bypass', 
            '-File', scriptPath,
            '-ChallengeData', challenge
        ]);

        let signature = "";
        ps.stdout.on('data', (data) => { signature += data.toString().trim(); });
        ps.on('close', (code) => {
            if (code !== 0 || signature.includes("ERROR")) {
                console.error("[SIGN] Failed");
                return res.status(500).json({ error: "Signing Failed", details: signature });
            }
            res.json({ status: "success", signature: signature });
        });
    } catch (e) {
        res.status(500).json({ error: "Internal Error", details: e.message });
    }
});

// ROUTE: SIGNUP (Enrollment) - FIXED!
// ROUTE: SIGNUP (Enrollment) - FIXED
app.post('/signup', (req, res) => {
    // 1. Parse ALL incoming parameters
    // CHANGED: 'role' -> 'serviceRoles'
    const { username, serviceRoles, email, orgUnit, org, state, country } = req.body;

    // 2. Validate
    if (!username || !serviceRoles || !email || !orgUnit || !org || !state || !country) {
        return res.status(400).json({ 
            status: "error", 
            message: "Missing fields. Ensure 'serviceRoles' is sent." 
        });
    }

    console.log(`[ENROLL] Starting enrollment for ${username}...`);
    console.log(`[ENROLL] Roles: ${JSON.stringify(serviceRoles)}`);

    try {
        const scriptPath = getScriptPath('signup.ps1');
        
        // 3. Spawn PowerShell with CORRECT arguments
        // CRITICAL FIX: Convert serviceRoles Object -> JSON String
        const serviceRolesString = JSON.stringify(serviceRoles);

        const ps = spawn('powershell.exe', [
            '-NoProfile', '-ExecutionPolicy', 'Bypass', 
            '-File', scriptPath,
            '-username', username, 
            '-serviceRoles', serviceRolesString, // CHANGED: Passing JSON string to -serviceRoles
            '-email', email,
            '-orgUnit', orgUnit,
            '-org', org,
            '-state', state,
            '-country', country
        ]);

        let scriptOutput = "";
        
        ps.stdout.on('data', (data) => { 
            const msg = data.toString();
            console.log(msg);
            scriptOutput += msg; 
        });

        ps.stderr.on('data', (data) => { 
            const msg = data.toString();
            console.error(msg); 
            scriptOutput += msg; 
        });

        ps.on('close', (code) => {
            console.log(`[ENROLL] Exit Code: ${code}`);

            try {
                // Parse the JSON output from PowerShell
                const jsonStartIndex = scriptOutput.indexOf('{');
                if (jsonStartIndex === -1) throw new Error("No JSON found in output");
                const cleanJsonString = scriptOutput.substring(jsonStartIndex);
                const parsedResult = JSON.parse(cleanJsonString);
                
                if(parsedResult.status === 'error') {
                    res.status(500).json(parsedResult);
                } else {
                    res.json(parsedResult);
                }

            } catch (e) {
                console.error("[ENROLL] Parse Error:", e.message);
                res.status(500).json({ 
                    status: "error", 
                    message: "Bridge parse failure", 
                    details: scriptOutput 
                });
            }
        });
    } catch (e) {
        res.status(500).json({ status: "error", message: "Execution failure", details: e.message });
    }
});
app.get('/health', (req, res) => res.json({ status: "online" }));

process.on('uncaughtException', (err) => {
    console.error("CRITICAL ERROR:", err.message);
    process.stdin.resume();
});

app.listen(PORT, () => {
    console.log(`HSM Bridge running on http://localhost:${PORT}`);
});