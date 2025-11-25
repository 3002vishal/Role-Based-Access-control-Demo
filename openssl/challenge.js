import crypto from "crypto";
import fs from "fs";
import path from "path";

// ==========================
// 1. GENERATE RANDOM CHALLENGE
// ==========================
export function generateChallenge() {
    const challenge = crypto.randomBytes(32).toString("base64"); 
    return challenge;
}

// ==========================
// 2. VERIFY SIGNATURE
// ==========================
// userCertName = ex: "rahul" -> loads backend/openssl/issued/rahul_cert.pem

export function verifySignature(userCertName, challenge, signatureBase64) {

    // Load user certificate (public key inside cert)
    const certPath = path.join(
        `${userCertName}_cert.pem`
    );

    if (!fs.existsSync(certPath)) {
        throw new Error("User certificate not found: " + certPath);
    }

    const userCert = fs.readFileSync(certPath, "utf8");

    // Prepare verifier
    const verify = crypto.createVerify("SHA256");
    verify.update(challenge);
    verify.end();

    const signature = Buffer.from(signatureBase64, "base64");

    // Verify using certificate public key
    const isValid = verify.verify(userCert, signature);

    return isValid;
}
