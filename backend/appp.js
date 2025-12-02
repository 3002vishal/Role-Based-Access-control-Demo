// ---------- File: backend/index.js ----------
// Pure PKI-based RBAC: role extracted from certificate OID (1.2.3.4.5.6.7.8.1)

const express = require("express");
const { exec } = require("child_process");
const { promisify } = require("util");
const fs = require("fs").promises;
const path = require("path");
const crypto = require("crypto");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();

const execAsync = promisify(exec);
const app = express();
app.use(cors());
app.use(express.json());

// -------------------------
// Database setup (username + cert_path + role)
// -------------------------
const db = new sqlite3.Database(path.join(__dirname, "certs.db"));
const dbRun = promisify(db.run.bind(db));
const dbGet = promisify(db.get.bind(db));

async function initDB() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS user_certs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      cert_path TEXT NOT NULL,
      role TEXT NOT NULL
    )
  `);
}
initDB().catch(console.error);

// -------------------------
// Config
// -------------------------
const PS_SCRIPT_PATH = path.resolve(__dirname, "..", "openssl", "issue_cert.ps1");
const CERT_DIR = path.join(__dirname, "cert");
fs.mkdir(CERT_DIR, { recursive: true }).catch(console.error);

const CHALLENGES = {}; // username -> Buffer

// -------------------------
// Helper: Execute PowerShell
// -------------------------
function executePowerShell(scriptPath, args) {
  const quotedArgs = args.map(a => `"${String(a).replace(/"/g, '\\"')}"`).join(" ");
  const cmd = `powershell.exe -ExecutionPolicy Bypass -File "${scriptPath}" ${quotedArgs}`;
  return execAsync(cmd);
}

// -------------------------
// Helper: Verify cert chain
// -------------------------
async function verifyCertChain(clientCertPath) {
  const rootPath = path.resolve(__dirname, "..", "openssl", "demoCA", "root", "ca.cert.pem");
  const intermediateDir = path.resolve(__dirname, "..", "openssl", "demoCA", "intermediate");
  const chainPath = path.join(intermediateDir, "chain.pem");
  const intCertPath = path.join(intermediateDir, "int.cert.pem");

  await fs.access(clientCertPath);
  await fs.access(rootPath);

  let untrustedFile = intCertPath;
  try {
    await fs.access(chainPath);
    untrustedFile = chainPath;
    console.log("✅ Using chain.pem for verification");
  } catch {
    console.warn("⚠️ chain.pem not found, falling back to int.cert.pem");
  }

  const cmd = `openssl verify -CAfile "${rootPath}" -untrusted "${untrustedFile}" "${clientCertPath}"`;
  const { stdout } = await execAsync(cmd);

  if (!stdout.includes(": OK"))
    throw new Error(`Certificate chain verification failed: ${stdout}`);
  return true;
}

// -------------------------
// Helper: Extract role from certificate OID
// -------------------------
async function extractRoleFromCert(certPath) {
  try {
    const { stdout } = await execAsync(`openssl x509 -in "${certPath}" -noout -text`);
    const regex = /1\.2\.3\.4\.5\.6\.7\.8\.1\s*:\s*(.+)/;
    const match = stdout.match(regex);

    if (match && match[1]) {
      const role = match[1].replace(/[.\s]+/g, "").trim().toLowerCase();
      console.log(`✅ Extracted role from certificate: ${role}`);
      return role;
    }

    console.warn(" No role OID found in certificate.");
    return null;
  } catch (err) {
    console.error("Failed to extract role:", err.message);
    return null;
  }
}

// -------------------------
// Enroll route (issues certificate)
// -------------------------
app.post("/enroll", async (req, res) => {
  try {
    const { username, role } = req.body;
    console.log("Received enroll request:", username, role);

    if (!username || !role)
      return res.status(400).json({ error: "username and role required" });

    const args = ["-CN", username, "-ROLE", role, "-TYPE", "client", "-OUTDIR", CERT_DIR];
    console.log("Running PowerShell with args:", args);

    // Execute PowerShell script
    const { stdout, stderr } = await executePowerShell(PS_SCRIPT_PATH, args);
    console.log("PowerShell stdout:", stdout);
    if (stderr) console.error("PowerShell stderr:", stderr);

    const certFile = path.join(CERT_DIR, `${username}.cert.pem`);
    const keyFile = path.join(CERT_DIR, `${username}.key.pem`);

    await fs.access(certFile);
    await fs.access(keyFile);

    // Save in DB (with role)
    const existingUser = await dbGet("SELECT * FROM user_certs WHERE username = ?", [username]);
    if (existingUser) {
      await dbRun("UPDATE user_certs SET cert_path = ?, role = ? WHERE username = ?", [certFile, role, username]);
    } else {
      await dbRun("INSERT INTO user_certs (username, cert_path, role) VALUES (?, ?, ?)", [username, certFile, role]);
    }

    // Read and delete key file
    const keyContent = await fs.readFile(keyFile);
    try { await fs.unlink(keyFile); } catch (e) { console.warn("Could not delete key file:", e.message); }

    res.json({
      username,
      role,
      private_key_b64: keyContent.toString("base64"),
    });

  } catch (error) {
    console.error("Enrollment error:", error);
    res.status(500).json({
      error: "Failed to issue certificate",
      details: error.message,
    });
  }
});

// -------------------------
// Login challenge
// -------------------------
app.post("/login-challenge", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "username required" });

    const dbUser = await dbGet("SELECT * FROM user_certs WHERE username = ?", [username]);
    if (!dbUser) return res.status(404).json({ error: "User not enrolled" });

    const challenge = crypto.randomBytes(32);
    CHALLENGES[username] = challenge;

    res.json({ challenge: challenge.toString("base64") });
  } catch (error) {
    console.error("Challenge error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------------
// Login verify (PKI-only)
// -------------------------
app.post("/login-verify", async (req, res) => {
  try {
    const { username, signature: signatureB64 } = req.body;
    if (!username || !signatureB64)
      return res.status(400).json({ error: "username and signature required" });

    const dbUser = await dbGet("SELECT * FROM user_certs WHERE username = ?", [username]);
    if (!dbUser) return res.status(404).json({ error: "User not enrolled" });

    await verifyCertChain(dbUser.cert_path);

    const challenge = CHALLENGES[username];
    if (!challenge)
      return res.status(400).json({ error: "No challenge found. Request a challenge first." });

    const certData = await fs.readFile(dbUser.cert_path);
    const cert = new crypto.X509Certificate(certData);
    const publicKey = cert.publicKey;

    const signature = Buffer.from(signatureB64, "base64");
    const verify = crypto.createVerify("SHA256");
    verify.update(challenge);
    const isValid = verify.verify(publicKey, signature);
    if (!isValid) return res.status(401).json({ error: "Signature verification failed" });

    const roleFromCert = await extractRoleFromCert(dbUser.cert_path);
    if (!roleFromCert)
      return res.status(400).json({ error: "Role not found in certificate" });

    delete CHALLENGES[username];
    res.json({ message: "Login successful", username, role: roleFromCert });
  } catch (error) {
    console.error("Verification error:", error);
    res.status(401).json({ error: "Verification failed", details: error.message });
  }
});

// -------------------------
// Role-based middleware
// -------------------------
function roleRequiredCert(allowedRoles) {
  return async (req, res, next) => {
    try {
      const { username, signature: signatureB64 } = req.body;
      if (!username || !signatureB64)
        return res.status(400).json({ error: "username and signature required" });

      const dbUser = await dbGet("SELECT * FROM user_certs WHERE username = ?", [username]);
      if (!dbUser) return res.status(404).json({ error: "User not enrolled" });

      await verifyCertChain(dbUser.cert_path);

      const challenge = CHALLENGES[username];
      if (!challenge)
        return res.status(400).json({ error: "No challenge found. Request a challenge first." });

      const certData = await fs.readFile(dbUser.cert_path);
      const cert = new crypto.X509Certificate(certData);
      const publicKey = cert.publicKey;

      const signature = Buffer.from(signatureB64, "base64");
      const verify = crypto.createVerify("SHA256");
      verify.update(challenge);
      const isValid = verify.verify(publicKey, signature);
      if (!isValid) return res.status(401).json({ error: "Signature verification failed" });

      const roleFromCert = await extractRoleFromCert(dbUser.cert_path);
      if (!roleFromCert)
        return res.status(400).json({ error: "Role not found in certificate" });

      if (!allowedRoles.includes(roleFromCert))
        return res.status(403).json({ error: "Forbidden: insufficient role" });

      req.user = { username, role: roleFromCert };
      delete CHALLENGES[username];
      next();
    } catch (error) {
      console.error("Role auth error:", error);
      res.status(401).json({ error: "Certificate verification failed", details: error.message });
    }
  };
}

// -------------------------
// Role-based endpoints
// -------------------------
app.post("/admin-data", roleRequiredCert(["admin"]), (req, res) => {
  res.json({ message: `Welcome Admin ${req.user.username}!` });
});

app.post("/viewer-data", roleRequiredCert(["viewer"]), (req, res) => {
  res.json({ message: `Hello ${req.user.username}, you can view data.` });
});

app.post("/editor-data", roleRequiredCert(["editor"]), (req, res) => {
  res.json({ message: `Hello ${req.user.username}, you can edit data.` });
});

// -------------------------
// Start server
// -------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
});
