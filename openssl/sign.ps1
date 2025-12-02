# File: sign.ps1 (Legacy/Compatible Version)
param(
    [string]$ChallengeData
)

# 1. Load Security Assembly
Add-Type -AssemblyName System.Security

# 2. Open Store
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$store.Open("ReadOnly")

# 3. Select Certificate
$certs = $store.Certificates.Find("FindByTimeValid", [DateTime]::Now, $false)
$selection = [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection(
    $certs, "Select Token", "Pick your hardware certificate", "SingleSelection"
)

if ($selection.Count -eq 0) {
    Write-Output "ERROR:User_Cancelled"
    exit
}
$cert = $selection[0]

try {
    # 4. Get Private Key (The "Old Reliable" Way)
    # We cast it explicitly to RSACryptoServiceProvider
    $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]$cert.PrivateKey

    if ($null -eq $rsa) {
        Write-Output "ERROR:No_Private_Key_Found"
        exit
    }

    # 5. Sign Data (Simpler Legacy Syntax)
    # Convert string to bytes
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($ChallengeData)
    
    # Sign using SHA256. 
    # Note: older providers use "SHA256" string, not the complex object.
    $signatureBytes = $rsa.SignData($dataBytes, "SHA256")

    # 6. Output
    $signatureBase64 = [Convert]::ToBase64String($signatureBytes)
    Write-Output $signatureBase64

} catch {
    # Debug info if it still fails
    Write-Host "--------------- ERROR DETAILS ---------------" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Write-Host "---------------------------------------------" -ForegroundColor Red
    exit
}