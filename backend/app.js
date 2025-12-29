const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
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

// Store active challenges: { "username": "random_string_nonce" }
const challenges = {};

// ==============================
// Helper: Get Role from Cert (Disk)
// ==============================
function getRoleFromCert(username) {
  try {
    const certPath = path.join(CERT_DIR, `${username}_cert.pem`);
    if (!fs.existsSync(certPath)) return null;

    const certPem = fs.readFileSync(certPath, "utf8");
    const cert = forge.pki.certificateFromPem(certPem);

    const roleExt = cert.extensions.find((ext) => ext.id === "1.2.3.4.5.6.7.8.1");
    if (!roleExt || !roleExt.value) return "viewer"; 

    const raw = roleExt.value.toString().toLowerCase();
    if (raw.includes("admin")) return "admin";
    if (raw.includes("editor")) return "editor";
    
    return "viewer";
  } catch (err) {
    console.error(`Error reading role for ${username}:`, err.message);
    return null;
  }
}

// ==============================
// 1. Enrollment (No Change)
// ==============================
app.post("/api/enroll", (req, res) => {
  const { username, csr, role } = req.body;
  if (!username || !csr || !role) return res.status(400).json({ error: "Missing fields" });

  const csrString = Array.isArray(csr) ? csr.join("\r\n") : String(csr);
  const csrPath = path.join(CERT_DIR, `${username}_req.csr`);
  const certPath = path.join(CERT_DIR, `${username}_cert.pem`);

  try { fs.writeFileSync(csrPath, csrString); } catch (e) { return res.status(500).json({ error: "Write failed" }); }

  let ext = "role_viewer";
  if (role === "admin") ext = "role_admin";
  if (role === "editor") ext = "role_editor";

  // IMPORTANT: Ensure openssl.cnf and CA keys exist
  const cmd = `openssl x509 -req -in "${csrPath}" -CA demoCA/intermediate/int.cert.pem -CAkey demoCA/intermediate/private/int.key.pem -CAcreateserial -out "${certPath}" -days 365 -extfile openssl.cnf -extensions ${ext}`;

  exec(cmd, (error, stdout, stderr) => {
    if (fs.existsSync(csrPath)) fs.unlinkSync(csrPath); // Cleanup
    if (error) {
      console.error("OpenSSL Error:", stderr);
      return res.status(500).json({ error: "Signing failed" });
    }
    const signedCert = fs.readFileSync(certPath, "utf8");
    return res.json({ success: true, certificate: signedCert });
  });
});

// ==============================
// 2. Challenge Endpoint
// ==============================
// Client MUST call this before EVERY protected request
app.get("/auth/challenge/:user", (req, res) => {
  const user = req.params.user;
  // Generate a random 32-byte nonce
  const challenge = crypto.randomBytes(32).toString("base64");
  
  // Store it (overwrites any previous challenge for this user)
  challenges[user] = challenge;
  
  console.log(`[Challenge] Generated for ${user}: ${challenge.substring(0, 10)}...`);
  res.json({ challenge });
});

// ==============================
// 3. Secure Middleware (Verification)
// ==============================
// This replaces the old "stateless" requireRole. 
// It performs Authentication (Sig Check) AND Authorization (Role Check) at once.
const verifyAccess = (allowedRoles = []) => (req, res, next) => {
  const { username, signature } = req.body;

  // 1. Input Validation
  if (!username || !signature) {
    return res.status(400).json({ 
      error: "Authentication Failed: Missing 'username' or 'signature' in body." 
    });
  }

  // 2. Retrieve Active Challenge
  const challenge = challenges[username];
  if (!challenge) {
    return res.status(401).json({ 
      error: "Session Expired or Invalid. Please request a new challenge at /auth/challenge/:user" 
    });
  }

  // 3. Verify Signature
  const certPath = path.join(CERT_DIR, `${username}_cert.pem`);
  if (!fs.existsSync(certPath)) {
    return res.status(404).json({ error: "User certificate not found on server." });
  }

  try {
    const certPem = fs.readFileSync(certPath, "utf8");
    const publicKey = crypto.createPublicKey(certPem);
    const sigBuff = Buffer.from(signature, "base64");
    
    // Verify that the signature matches the stored challenge
    const isValid = crypto.verify("sha256", Buffer.from(challenge), publicKey, sigBuff);

    if (!isValid) {
      console.warn(`[Security] Invalid signature attempt for ${username}`);
      return res.status(403).json({ error: "Invalid Signature. Authentication failed." });
    }

    // 4. Consume Challenge (Prevent Replay Attacks)
    // Once used, the challenge is deleted. The client must ask for a new one for the next request.
    delete challenges[username]; 

    // 5. Role-Based Access Control (RBAC)
    const userRole = getRoleFromCert(username);
    console.log(`[Access] User: ${username} | Role: ${userRole} | Target: ${req.originalUrl}`);

    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({ error: "Access Denied: Insufficient Privileges." });
    }

    // If we get here, Auth & Role are valid. Proceed to controller.
    next();

  } catch (err) {
    console.error("Verification Error:", err);
    return res.status(500).json({ error: "Internal Server Error during verification." });
  }
};

// ==============================
// 4. Protected Routes
// ==============================

// NOTE: All these routes now expect { username, signature, ...otherData } in the body

app.post("/api/pki", verifyAccess(["admin"]), (req, res) => {
  res.json({ data: "SECRET ADMIN DATA - PKI CONFIG" });
});

app.post("/api/hsm", verifyAccess(["editor", "admin"]), (req, res) => {
  res.json({ data: "HSM CONFIGURATION PANEL" });
});

app.post("/api/identity", verifyAccess(["viewer", "editor", "admin"]), (req, res) => {
  res.json({ data: "IDENTITY LIST (READ ONLY)" });
});

app.post("/api/security", verifyAccess(["admin"]), (req, res) =>{
  res.json({ data: "SECURITY AUDIT LOGS" });
});

app.post("/api/zero-trust", verifyAccess(["admin", "editor"]), (req, res) =>{
  res.json({ data: "ZERO TRUST POLICY SETTINGS" });
});

app.post("/api/crypto", verifyAccess(["viewer", "editor"]), (req, res) =>{
  // verifyAccess has already run, so we know 'req.body.username' is authentic
  console.log("Crypto payload received:", req.body);
  res.json({ data: "CRYPTOGRAPHIC STATS" });
});

// ==============================
// Start Server
// ==============================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log("Mode: STRICT Challenge-Response per request");
});