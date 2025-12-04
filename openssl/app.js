import express from "express";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { exec } from "child_process";
import cors from "cors";
import { fileURLToPath } from "url";
import { dirname } from "path";
import forge from "node-forge";

const app = express();
const PORT = 5000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ==============================
// Middleware
// ==============================
app.use(express.json({ limit: "50mb" }));
// Allow your frontend origin explicitly in production. origin: true is ok for local dev
app.use(cors({ origin: true, credentials: false }));

// In-memory one-time challenges. (Still stateless w.r.t. sessions)
const challenges = {};

// ==============================
// Helper: read role from certificate
// ==============================
function getRoleFromCert(username) {
  try {
    const certPath = path.join(__dirname, `${username}_cert.pem`);
    if (!fs.existsSync(certPath)) {
      console.warn(`Certificate not found for ${username}`);
      return null;
    }

    const certPem = fs.readFileSync(certPath, "utf8");
    const cert = forge.pki.certificateFromPem(certPem);

    // Adjust this OID to the real one you use
    const roleExt = cert.extensions.find((ext) => ext.id === "1.2.3.4.5.6.7.8.1");

    if (!roleExt || !roleExt.value) {
      return "viewer"; // default role
    }

    const raw = roleExt.value || "";
    if (raw.includes("admin")) return "admin";
    if (raw.includes("editor")) return "editor";
    return "viewer";
  } catch (err) {
    console.error("Error parsing certificate:", err);
    return null;
  }
}

// ==============================
// Enrollment (same behavior as before)
// ==============================
app.post("/api/enroll", (req, res) => {
  const { username, csr, role } = req.body;
  if (!username || !csr || !role) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const csrString = Array.isArray(csr) ? csr.join("\r\n") : String(csr);
  const csrFilename = `${username}_req.csr`;
  const certFilename = `${username}_cert.pem`;

  try {
    fs.writeFileSync(csrFilename, csrString);
  } catch (err) {
    console.error("Failed to write CSR:", err);
    return res.status(500).json({ error: "Failed to save CSR" });
  }

  let extensionSection = "role_viewer";
  if (role === "admin") extensionSection = "role_admin";
  if (role === "editor") extensionSection = "role_superuser";

  const command = `openssl x509 -req -in "${csrFilename}" -CA demoCA/intermediate/int.cert.pem -CAkey demoCA/intermediate/private/int.key.pem -CAcreateserial -out "${certFilename}" -days 365 -extfile openssl.cnf -extensions ${extensionSection}`;

  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error("[OpenSSL] ", stderr || error.message);
      // Cleanup csr file if present
      try { if (fs.existsSync(csrFilename)) fs.unlinkSync(csrFilename); } catch (e) {}
      return res.status(500).json({ error: "Signing failed", details: stderr || error.message });
    }

    try {
      const signedCert = fs.readFileSync(certFilename, "utf8");
      if (fs.existsSync(csrFilename)) fs.unlinkSync(csrFilename);
      return res.json({ success: true, certificate: signedCert });
    } catch (readErr) {
      console.error(readErr);
      return res.status(500).json({ error: "Could not read generated certificate" });
    }
  });
});

// ==============================
// Challenge endpoint (one-time token)
// ==============================
app.get("/auth/challenge/:user", (req, res) => {
  const user = req.params.user;
  const challenge = crypto.randomBytes(32).toString("base64");
  challenges[user] = challenge;
  // You may set an expiration strategy (e.g. store timestamp and periodically clear expired)
  res.json({ challenge });
});

// ==============================
// Optional: single verify endpoint (doesn't create session)
// This just verifies signature and returns the role (stateless).
// ==============================
app.post("/auth/verify", (req, res) => {
  const { username, signature } = req.body;
  if (!username || !signature) return res.status(400).json({ error: "Missing fields" });

  if (!challenges[username]) return res.status(400).json({ error: "No active challenge" });

  const challenge = challenges[username];
  const certPath = path.join(__dirname, `${username}_cert.pem`);
  if (!fs.existsSync(certPath)) return res.status(404).json({ error: "Certificate not found" });

  try {
    const certPem = fs.readFileSync(certPath, "utf8");
    const publicKey = crypto.createPublicKey(certPem);
    const signatureBuffer = Buffer.from(signature, "base64");

    const isValid = crypto.verify("sha256", Buffer.from(challenge), publicKey, signatureBuffer);
    // consume the challenge regardless of outcome to avoid replay
    delete challenges[username];

    if (!isValid) return res.status(403).json({ success: false, msg: "Signature INVALID" });

    const role = getRoleFromCert(username);
    if (!role) return res.status(500).json({ error: "Could not determine role from cert" });

    return res.json({ success: true, role });
  } catch (err) {
    console.error("Verification error:", err);
    return res.status(500).json({ error: "Verification error" });
  }
});

// ==============================
// Stateless RBAC middleware
// Expects request body: { username, challenge, signature }
// ==============================
const requireRole = (allowedRoles = []) => (req, res, next) => {
  const { username, challenge, signature } = req.body;

  

 

  

    const role = getRoleFromCert(username);
    

    if (!allowedRoles.includes(role)) {
      return res.status(403).json({ error: "Access Denied" });
    }

    // attach user info to request for route handlers if needed
  
    return next();

};

// ==============================
// Protected routes (use POST so you can send JSON body)
// ==============================
app.post("/api/admin-data", requireRole(["admin"]), (req, res) => {
  res.json({ data: "SECRET ADMIN DATA", user: req.user });
});

app.post("/api/editor-data", requireRole(["editor"]), (req, res) => {
  res.json({ data: "EDITOR CONTENT", user: req.user });
});

app.post("/api/viewer-data", requireRole(["viewer", "editor", "admin"]), (req, res) => {
  // viewer route also allows higher roles
  res.json({ data: "VIEWER DATA", user: req.user });
});

// ==============================
app.listen(PORT, () => {
  console.log(`Stateless PKI server running on http://localhost:${PORT}`);
});
