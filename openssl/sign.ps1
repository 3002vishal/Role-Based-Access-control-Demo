# File: sign.ps1 (Universal Version)
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

# 2. Check if Private Key exists at all
if ($cert.HasPrivateKey -eq $false) {
    Write-Output "ERROR:No_Private_Key_Found (You picked a Public-Only certificate. Try the other one?)"
    exit
}

try {
    # 3. Convert Input to Bytes
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($ChallengeData)
    $signatureBytes = $null

    # 4. Attempt Signing (Try Modern Method First, then Legacy)
    try {
        # Modern CNG Method (For newer tokens)
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if ($rsa) {
            $signatureBytes = $rsa.SignData($dataBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }
    } catch {
        # Ignore error and fall through to legacy
    }

    # Fallback to Legacy Method (For older tokens/drivers)
    if ($null -eq $signatureBytes) {
        $rsaLegacy = $cert.PrivateKey
        if ($rsaLegacy -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            $signatureBytes = $rsaLegacy.SignData($dataBytes, "SHA256")
        }
    }

    if ($null -eq $signatureBytes) {
        Write-Output "ERROR:Could_Not_Sign_With_This_Token"
        exit
    }

    # 5. Success Output
    $signatureBase64 = [Convert]::ToBase64String($signatureBytes)
    Write-Output $signatureBase64

} catch {
    Write-Host "ERROR:Critical_Failure"
    Write-Host $_.Exception.Message
    exit
}