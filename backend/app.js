const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process"); 
const cors = require("cors");
const forge = require("node-forge");

const app = express();
const PORT = 5000;

const CERT_DIR = path.join(__dirname, "cert");
if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

// ==============================
// Middleware
// ==============================
app.use(express.json({ limit: "50mb" }));
app.use(cors({ origin: true, credentials: false }));

const challenges = {};

// ==============================
// Helper: Get Service Roles from Cert
// ==============================
function getServiceRoles(username) {
  try {
    const certPath = path.join(CERT_DIR, `${username}_cert.pem`);
    if (!fs.existsSync(certPath)) return {};

    const certPem = fs.readFileSync(certPath, "utf8");
    const cert = forge.pki.certificateFromPem(certPem);

    const roleExt = cert.extensions.find((ext) => ext.id === "1.2.3.4.5.6.7.8.1");
    if (!roleExt || !roleExt.value) return {}; 

    const rawString = roleExt.value.toString('utf8');
    const jsonMatch = rawString.match(/\{.*\}/); 
    
    if (jsonMatch) {
        return JSON.parse(jsonMatch[0]); 
    }
    return {};

  } catch (err) {
    console.error(`Error reading roles for ${username}:`, err.message);
    return {};
  }
}

// ==============================
// 1. Enrollment ( untouched )
// ==============================
app.post("/api/enroll", (req, res) => {
  const { username, csr, serviceRoles } = req.body;
  if (!username || !csr || !serviceRoles) {
      return res.status(400).json({ error: "Missing fields" });
  }

  const csrString = Array.isArray(csr) ? csr.join("\r\n") : String(csr);
  const csrPath = path.join(CERT_DIR, `${username}_req.csr`);
  const certPath = path.join(CERT_DIR, `${username}_cert.pem`);

  try { fs.writeFileSync(csrPath, csrString); } catch (e) { return res.status(500).json({ error: "Write failed" }); }

  const envVars = { ...process.env, SERVICE_ROLES: serviceRoles };

  const args = [
    'x509', '-req',
    '-in', csrPath,
    '-CA', 'demoCA/intermediate/int.cert.pem',
    '-CAkey', 'demoCA/intermediate/private/int.key.pem',
    '-CAcreateserial',
    '-out', certPath,
    '-days', '365',
    '-extfile', 'openssl.cnf',
    '-extensions', 'usr_cert_dynamic'
  ];

  console.log(`[Enroll] Signing for ${username} with roles: ${serviceRoles}`);
  const openssl = spawn('openssl', args, { env: envVars });

  openssl.on('close', (code) => {
    if (fs.existsSync(csrPath)) fs.unlinkSync(csrPath); 
    if (code === 0) {
        const signedCert = fs.readFileSync(certPath, "utf8");
        return res.json({ success: true, certificate: signedCert });
    } else {
        return res.status(500).json({ error: "Signing failed" });
    }
  });
  openssl.stderr.on('data', (data) => console.error(`OpenSSL Stderr: ${data}`));
});

// ==============================
// 2. Challenge Endpoint
// ==============================
app.get("/auth/challenge/:user", (req, res) => {
  const user = req.params.user;
  const challenge = crypto.randomBytes(32).toString("base64");
  challenges[user] = challenge;
  res.json({ challenge });
});

// ==============================
// 3. LOGIN ENDPOINT (NEW)
// ==============================
// This endpoint verifies the user has a valid certificate and matching key.
// If valid, it returns the Service Matrix so the frontend knows what to display.
app.post("/api/login", (req, res) => {
    const { username, signature } = req.body;

    if (!username || !signature) return res.status(400).json({ error: "Missing Auth Data" });

    // 1. Get Challenge
    const challenge = challenges[username];
    if (!challenge) return res.status(401).json({ error: "Session Expired or Invalid" });

    // 2. Get Certificate
    const certPath = path.join(CERT_DIR, `${username}_cert.pem`);
    if (!fs.existsSync(certPath)) return res.status(404).json({ error: "User certificate not found." });

    try {
        const certPem = fs.readFileSync(certPath, "utf8");
        const publicKey = crypto.createPublicKey(certPem);
        
        // 3. Verify Signature
        const sigBuff = Buffer.from(signature, "base64");
        const isValid = crypto.verify("sha256", Buffer.from(challenge), publicKey, sigBuff);

        if (!isValid) {
            return res.status(403).json({ error: "Invalid Signature. Access Denied." });
        }

        // 4. Success! Clear challenge and get Roles
        delete challenges[username];
        const roles = getServiceRoles(username);

        console.log(`[Login] Successful login for ${username}. Roles:`, roles);
        
        // Return the roles to the frontend
        res.json({ 
            success: true, 
            message: "Login Successful",
            user: username,
            roles: roles // e.g., { ZTA: "Admin", PKI: "Viewer" }
        });

    } catch (err) {
        console.error("Login Error:", err);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

// ==============================
// 4. Secure Middleware (RBAC)
// ==============================
const verifyAccess = (requiredService, allowedRoles = []) => (req, res, next) => {
  const { username, signature } = req.body;

  if (!username || !signature) return res.status(400).json({ error: "Missing Auth Data" });

  const challenge = challenges[username];
  if (!challenge) return res.status(401).json({ error: "Session Expired" });

  const certPath = path.join(CERT_DIR, `${username}_cert.pem`);
  if (!fs.existsSync(certPath)) return res.status(404).json({ error: "Cert not found" });

  try {
    const certPem = fs.readFileSync(certPath, "utf8");
    const publicKey = crypto.createPublicKey(certPem);
    const sigBuff = Buffer.from(signature, "base64");
    const isValid = crypto.verify("sha256", Buffer.from(challenge), publicKey, sigBuff);

    if (!isValid) return res.status(403).json({ error: "Invalid Signature" });
    delete challenges[username]; 

    // --- RBAC CHECK ---
    const userRoleMatrix = getServiceRoles(username);
    const userRoleForService = userRoleMatrix[requiredService]; 

    console.log(`[Access] User: ${username} | Service: ${requiredService} | Role: ${userRoleForService}`);

    if (!userRoleForService || !allowedRoles.includes(userRoleForService)) {
      return res.status(403).json({ 
          error: `Access Denied. You are '${userRoleForService || 'Nothing'}' in '${requiredService}', but need: ${allowedRoles.join(' or ')}` 
      });
    }

    next();

  } catch (err) {
    console.error("Verification Error:", err);
    return res.status(500).json({ error: "Internal Error" });
  }
};

// ==============================
// 5. Protected Routes
// ==============================
// These remain the same. They enforce specific roles.

app.post("/api/pki", verifyAccess("PKI", ["administrator","operator"]), (req, res) => {
  res.json({ data: "SECRET ADMIN DATA - PKI CONFIG" });
});

app.post("/api/hsm", verifyAccess("HSM", ["hr", "administrator"]), (req, res) => {
  res.json({ data: "HSM CONFIGURATION PANEL" });
});

app.post("/api/identity", verifyAccess("IAM", ["operator", "hr", , "viewer"]), (req, res) => {
  res.json({ data: "IDENTITY LIST (READ ONLY)" });
});

app.post("/api/zero-trust", verifyAccess("ZTA", ["operator"]), (req, res) =>{
  res.json({ data: "ZERO TRUST POLICY SETTINGS" });
});

app.post("/api/security", verifyAccess("Security", [ "Operator"]), (req, res) =>{
  res.json({ data: "SECURITY ALERTS DASHBOARD" });
});

app.post("/api/crypto", verifyAccess("Crypto", ["Admin", "Viewer"]), (req, res) =>{
  res.json({ data: "CRYPTO ANALYTICS" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});