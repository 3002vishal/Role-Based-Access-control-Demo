const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const cors = require("cors");
const forge = require("node-forge");

const app = express();
const PORT = 5000;

// NOTE: In CommonJS, __dirname is available automatically. 
// We don't need fileURLToPath or import.meta.url.

// ===================================================
// Create certificates folder
// ===================================================
const CERT_DIR = path.join(__dirname, "cert");
if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

// ==============================
// Middleware
// ==============================
app.use(express.json({ limit: "50mb" }));
app.use(cors({ origin: true, credentials: false }));

// In-memory challenges
const challenges = {};

// ==============================
// Helper: read role from certificate
// ==============================
function getRoleFromCert(username) {
  try {
    const certPath = path.join(CERT_DIR, `${username}_cert.pem`);

    if (!fs.existsSync(certPath)) {
      console.warn(`Certificate not found for ${username}`);
      return null;
    }

    const certPem = fs.readFileSync(certPath, "utf8");
    const cert = forge.pki.certificateFromPem(certPem);

    const roleExt = cert.extensions.find(
      (ext) => ext.id === "1.2.3.4.5.6.7.8.1"
    );

    if (!roleExt || !roleExt.value) {
        // Fallback or just return null
        return "viewer"; 
    }

    // forge returns the raw bytes for the extension value sometimes, 
    // so we ensure it's a string.
    const raw = roleExt.value.toString().toLowerCase();
    
    console.log("role data:", raw);
    
    if (raw.includes("admin")) return "admin";
    if (raw.includes("editor")) return "editor";
    if (raw.includes("viewer")) return "viewer";
    
    return "viewer"; // Default fallback
  } catch (err) {
    console.error("Error parsing certificate:", err);
    return null;
  }
}

// ==============================
// Enrollment (CSR → signed cert)
// ==============================
app.post("/api/enroll", (req, res) => {
  const { username, csr, role } = req.body;

  if (!username || !csr || !role) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const csrString = Array.isArray(csr) ? csr.join("\r\n") : String(csr);
  const csrPath = path.join(CERT_DIR, `${username}_req.csr`);
  const certPath = path.join(CERT_DIR, `${username}_cert.pem`);

  try {
    fs.writeFileSync(csrPath, csrString);
  } catch (err) {
    console.error("Failed to write CSR:", err);
    return res.status(500).json({ error: "Failed to save CSR" });
  }
  console.log("Requested role:", role);

  let ext = "role_viewer";
  if (role === "admin") ext = "role_admin";
  if (role === "editor") ext = "role_editor";

  // Ensure you have "openssl.cnf" and "demoCA" folders in the same directory as app.js
  const cmd = `openssl x509 -req -in "${csrPath}" -CA demoCA/intermediate/int.cert.pem -CAkey demoCA/intermediate/private/int.key.pem -CAcreateserial -out "${certPath}" -days 365 -extfile openssl.cnf -extensions ${ext}`;

  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      console.error("[OpenSSL Error]", stderr || error.message);
      try {
        if (fs.existsSync(csrPath)) fs.unlinkSync(csrPath);
      } catch (e) {}
      return res.status(500).json({ error: "Signing failed (Check OpenSSL logs)" });
    }

    try {
      const signedCert = fs.readFileSync(certPath, "utf8");
      // Clean up CSR
      if (fs.existsSync(csrPath)) fs.unlinkSync(csrPath);
      
      return res.json({ success: true, certificate: signedCert });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Could not read generated certificate" });
    }
  });
});

// ==============================
// Challenge endpoint
// ==============================
app.get("/auth/challenge/:user", (req, res) => {
  const user = req.params.user;
  const challenge = crypto.randomBytes(32).toString("base64");
  challenges[user] = challenge;
  res.json({ challenge });
});

// ==============================
// Signature verification
// ==============================
app.post("/auth/verify", (req, res) => {
  const { username, signature } = req.body;

  if (!username || !signature)
    return res.status(400).json({ error: "Missing fields" });

  if (!challenges[username])
    return res.status(400).json({ error: "No active challenge" });

  const challenge = challenges[username];
  delete challenges[username]; // One-time use

  const certPath = path.join(CERT_DIR, `${username}_cert.pem`);
  if (!fs.existsSync(certPath)) {
    return res.status(404).json({ error: "Certificate not found" });
  }

  try {
    const certPem = fs.readFileSync(certPath, "utf8");
    const publicKey = crypto.createPublicKey(certPem);
    const sigBuff = Buffer.from(signature, "base64");

    const valid = crypto.verify("sha256", Buffer.from(challenge), publicKey, sigBuff);

    if (!valid) return res.status(403).json({ success: false, msg: "Signature INVALID" });

    const role = getRoleFromCert(username);
    return res.json({ success: true, role });

  } catch (err) {
    console.error("Verification error:", err);
    return res.status(500).json({ error: "Verification error" });
  }
});

// ==============================
// Stateless RBAC middleware
// ==============================
const requireRole = (allowedRoles = []) => (req, res, next) => {
  const { username } = req.body;

  // In a real app, you would verify the signature AGAIN here 
  // or use a JWT. For this demo, we trust the username if the 
  // previous /verify step succeeded in the frontend flow.
  // (Ideally, this middleware should check a token, not just read the cert from disk).
  
  const role = getRoleFromCert(username);
  console.log(`Checking Access: User=${username}, Role=${role}`);
  
  if (!role) return res.status(404).json({ error: "Role not found in certificate" });

  if (!allowedRoles.includes(role)) {
    return res.status(403).json({ error: "Access Denied: Insufficient Privileges" });
  }

  next();
};

// ==============================
// Protected routes
// ==============================
app.post("/api/admin-data", requireRole(["admin"]), (req, res) => {
  res.json({ data: "SECRET ADMIN DATA: System Logs, User Management, Keys" });
});

app.post("/api/editor-data", requireRole(["editor", "admin"]), (req, res) => {
  res.json({ data: "EDITOR CONTENT: Drafts, articles, media assets" });
});

app.post("/api/viewer-data", requireRole(["viewer", "editor", "admin"]), (req, res) => {
  res.json({ data: "VIEWER DATA: Public articles, read-only content" });
});

// ==============================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});