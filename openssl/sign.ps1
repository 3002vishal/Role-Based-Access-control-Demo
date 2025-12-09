# File: sign.ps1 (Fixed: Forced Provider Type 1)
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

    # --- ATTEMPT 1: DIRECT CSP RECONSTRUCTION (The Fix) ---
    try {
        # Get info from the certificate
        $privKeyInfo = $cert.PrivateKey.CspKeyContainerInfo
        
        # Build connection parameters
        $cspParams = New-Object System.Security.Cryptography.CspParameters
        
        # 1. Use the Provider Name from the cert (e.g. "SafeSign Standard...")
        $cspParams.ProviderName = $privKeyInfo.ProviderName
        
        # 2. FORCE ProviderType TO 1 (PROV_RSA_FULL)
        # This fixes the "Invalid provider type specified" error
        $cspParams.ProviderType = 1 
        
        $cspParams.KeyContainerName = $privKeyInfo.KeyContainerName
        $cspParams.KeyNumber = $privKeyInfo.KeyNumber
        $cspParams.Flags = [System.Security.Cryptography.CspProviderFlags]::UseExistingKey

        # Create the RSA signer
        $rsaDirect = New-Object System.Security.Cryptography.RSACryptoServiceProvider($cspParams)

        # Try SHA256 first
        try {
            $signatureBytes = $rsaDirect.SignData($dataBytes, "SHA256")
        }
        catch {
            # Fallback to SHA1 if token is old
            $signatureBytes = $rsaDirect.SignData($dataBytes, "SHA1")
        }
    }
    catch {
        $err1 = $_.Exception.Message
    }

    # --- ATTEMPT 2: STANDARD LEGACY (Backup) ---
    if ($null -eq $signatureBytes) {
        try {
            # Force cast to RSACryptoServiceProvider
            $rsaLegacy = [System.Security.Cryptography.RSACryptoServiceProvider]$cert.PrivateKey
            if ($rsaLegacy) {
                 $signatureBytes = $rsaLegacy.SignData($dataBytes, "SHA256")
            }
        } catch { $err2 = $_.Exception.Message }
    }

    # --- ATTEMPT 3: MODERN CNG (Last Resort) ---
    if ($null -eq $signatureBytes) {
        try {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            if ($rsa) {
                $signatureBytes = $rsa.SignData($dataBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            }
        } catch { $err3 = $_.Exception.Message }
    }

    # 5. Final Output
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