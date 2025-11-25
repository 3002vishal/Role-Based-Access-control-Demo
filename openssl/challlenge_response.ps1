# =========================================================
#  PKI CHALLENGE-RESPONSE (FINAL FIXED VERSION)
# =========================================================

Clear-Host
Write-Host "=========================================================" -ForegroundColor Yellow
Write-Host "      STARTING SECURE LOGIN SIMULATION (FINAL)"            -ForegroundColor Yellow
Write-Host "=========================================================" -ForegroundColor Yellow

# --- STEP 1: GENERATE CHALLENGE ---
Write-Host "`n[SERVER] 1. Generating Secure Challenge..." -ForegroundColor Cyan
$challengeText = "Login-Request-ID-" + (Get-Random)
$challengeBytes = [System.Text.Encoding]::UTF8.GetBytes($challengeText)
Write-Host "   -> Challenge Data: '$challengeText'" -ForegroundColor Gray

# --- STEP 2: SELECT CERTIFICATE ---
Write-Host "`n[CLIENT] 2. Selecting Identity..." -ForegroundColor Cyan
$cert = Get-ChildItem Cert:\CurrentUser\My | 
    Where-Object { $_.HasPrivateKey } | 
    Out-GridView -Title "Select your Vishalku Certificate" -OutputMode Single

if (-not $cert) { Write-Error "No certificate selected."; exit }
Write-Host "   -> User Selected: [$($cert.Subject)]" -ForegroundColor Green

# --- STEP 3: SIGNING (LEGACY MODE) ---
Write-Host "`n[CLIENT] 3. Signing Challenge with Hardware Token..." -ForegroundColor Cyan
try {
    # Use Legacy Key Access for Moserbear/SafeSign
    $rsaKey = $cert.PrivateKey
    $rsaProvider = [System.Security.Cryptography.RSACryptoServiceProvider]$rsaKey
    
    # Sign Data
    $signature = $rsaProvider.SignData($challengeBytes, "SHA256")
    Write-Host "   -> SUCCESS! Challenge Signed." -ForegroundColor Green
}
catch {
    Write-Error "   -> SIGNING FAILED! Details: $_"
    exit
}

# --- STEP 4: VERIFYING ---
Write-Host "`n[SERVER] 4. Verifying Credentials..." -ForegroundColor Cyan
$pubKey = $cert.PublicKey.Key
$rsaPublic = [System.Security.Cryptography.RSACryptoServiceProvider]$pubKey
$isValid = $rsaPublic.VerifyData($challengeBytes, "SHA256", $signature)

if ($isValid) {
    Write-Host "   -> [OK] Signature is VALID. User Identity Confirmed." -ForegroundColor Green
} else {
    Write-Error "   -> [FAIL] Signature INVALID."
    exit
}

# --- STEP 5: RBAC CHECK (WITH HEX DECODER) ---
Write-Host "`n[SERVER] 5. Checking Access Permissions (RBAC)..." -ForegroundColor Cyan
$roleOid = "1.2.3.4.5.6.7.8.1" 
$adminRoleFound = $false

foreach ($extension in $cert.Extensions) {
    if ($extension.Oid.Value -eq $roleOid) {
        # 1. Get the Raw Hex format that Windows provides
        $rawHex = $extension.Format($true)
        
        # 2. CLEANUP: Remove spaces and newlines
        $cleanHex = $rawHex -replace '\s', '' -replace '`n', ''

        # 3. DECODE: Convert Hex Bytes to ASCII Text
        $decodedText = ""
        try {
            for ($i = 0; $i -lt $cleanHex.Length; $i += 2) {
                # Grab 2 chars (1 byte)
                $byteHex = $cleanHex.Substring($i, 2)
                # Convert to integer
                $val = [Convert]::ToInt32($byteHex, 16)
                # Only keep printable characters (A-Z, 0-9, =, etc.)
                if ($val -ge 32 -and $val -le 126) { 
                    $decodedText += [char]$val 
                }
            }
        } catch { 
            # If decoding fails, just use the raw string
            $decodedText = $rawHex 
        }

        Write-Host "   -> Found OID Data (Hex): $cleanHex" -ForegroundColor DarkGray
        Write-Host "   -> Decoded Text: '$decodedText'" -ForegroundColor Yellow
        
        # 4. CHECK: Does the decoded text contain "admin"?
        if ($decodedText -match "admin") { 
            $adminRoleFound = $true 
        }
    }
}

Write-Host "`n---------------------------------------------------------" -ForegroundColor DarkGray
if ($adminRoleFound) {
    Write-Host "ACCESS GRANTED: WELCOME, ADMIN USER!" -ForegroundColor Green -BackgroundColor Black
} else {
    Write-Host "ACCESS DENIED: NOT AN ADMIN." -ForegroundColor Red -BackgroundColor Black
}
Write-Host "---------------------------------------------------------" -ForegroundColor DarkGray