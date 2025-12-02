import express from "express";
import session from "express-session";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { exec } from "child_process";
import cors from "cors"; 
import { fileURLToPath } from "url";
import { dirname } from "path";

const app = express();
const PORT = 5000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ==========================================
// 1. MIDDLEWARE SETUP
// ==========================================
app.use(express.json({ limit: '50mb' }));
app.use(cors({ origin: true, credentials: true })); 

app.use(session({
    secret: "my-secure-pki-secret-key", 
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, 
        httpOnly: true, 
        maxAge: 3600000 
    }
}));

let challenges = {}; 

// ==========================================
// 2. HELPER FUNCTIONS
// ==========================================
function getRoleFromCert(username) {
    try {
        const certPath = path.join(`${username}_cert.pem`);
        if (!fs.existsSync(certPath)) return null;

        const certPem = fs.readFileSync(certPath);
        const x509 = new crypto.X509Certificate(certPem);
        
        // Robust check for Role OIDs in the text
        const rawText = x509.toString();
        
        if (rawText.includes("admin")) return "admin";
        if (rawText.includes("editor")) return "editor";
        
        return "viewer"; 
    } catch (e) {
        console.error("Cert Parse Error:", e);
        return null;
    }
}

// ==========================================
// 3. ENROLLMENT ROUTE (FIXED)
// ==========================================
app.post("/api/enroll", (req, res) => {
    console.log(`[ENROLL] Request received from ${req.body.username}`);
    
    const { username, csr, role } = req.body;

    if (!username || !csr || !role) {
        return res.status(400).json({ error: "Missing fields" });
    }

    // --- FIX 1: Robust String Conversion (Fixes "Object" error) ---
    let csrString = csr;
    if (Array.isArray(csr)) {
        csrString = csr.join('\r\n');
    } else if (typeof csr !== 'string') {
        csrString = String(csr);
    }

    const csrFilename = `${username}_req.csr`;
    const certFilename = `${username}_cert.pem`;

    // --- FIX 2: Write File ONCE (Removed the duplicate buggy line) ---
    try {
        fs.writeFileSync(csrFilename, csrString);
        console.log(`[DEBUG] Saved CSR to ${csrFilename}`);
    } catch (err) {
        console.error("File Write Error:", err);
        return res.status(500).json({ error: "Failed to save CSR file on server" });
    }

    // --- FIX 3: Select Config Section (Matches your openssl.cnf) ---
    let extensionSection = "role_viewer"; 
    if (role === "admin") extensionSection = "role_admin";
    if (role === "editor") extensionSection = "role_superuser";

    console.log(`[CA] Signing for ${username} with role: ${role}`);

    // --- FIX 4: Single Line Command with Intermediate Paths ---
    // This uses the Intermediate CA path found in your screenshot.
    const command = `openssl x509 -req -in "${csrFilename}" -CA demoCA/intermediate/int.cert.pem -CAkey demoCA/intermediate/private/int.key.pem -CAcreateserial -out "${certFilename}" -days 365 -extfile openssl.cnf -extensions ${extensionSection}`;

    console.log(`[DEBUG] Executing: ${command}`);

    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`[OpenSSL Error] ${stderr}`);
            return res.status(500).json({ error: "Signing Failed", details: stderr });
        }

        try {
            const signedCert = fs.readFileSync(certFilename, "utf8");
            
            // Cleanup CSR
            if (fs.existsSync(csrFilename)) fs.unlinkSync(csrFilename);

            console.log(`[CA] Certificate issued successfully for ${username}`);
            res.json({ success: true, certificate: signedCert });

        } catch (readErr) {
            console.error(readErr);
            res.status(500).json({ error: "Could not read generated certificate" });
        }
    });
});

// ==========================================
// 4. LOGIN ROUTES
// ==========================================
app.get("/auth/challenge/:user", (req, res) => {
    const user = req.params.user;
    const challenge = crypto.randomBytes(32).toString("base64");
    challenges[user] = challenge;
    res.json({ challenge });
});

app.post("/auth/verify", (req, res) => {
    const { username, signature } = req.body;
    if (!challenges[username]) return res.status(400).json({ error: "No active challenge." });

    const challenge = challenges[username];
    const certPath = path.join(__dirname, `${username}_cert.pem`);
    console.log("I am looking for file at:", path.resolve(certPath));

    if (!fs.existsSync(certPath)) return res.status(404).json({ error: "Certificate not found." });

    try {
        const userCert = fs.readFileSync(certPath, "utf8");
        const verify = crypto.createVerify("SHA256");
        verify.update(challenge);
        verify.end();

        const signatureBuffer = Buffer.from(signature, "base64");
        const publicKey = crypto.createPublicKey(userCert);
        
        const isValid = crypto.verify("sha256", Buffer.from(challenge), publicKey, signatureBuffer);

        if (!isValid) return res.json({ success: false, msg: "Signature INVALID" });

        const role = getRoleFromCert(username);
        req.session.user = { username, role, loginTime: new Date() };
        delete challenges[username];

        console.log(`[LOGIN] User ${username} logged in as ${role}`);
        return res.json({ success: true, msg: "Login Successful", role: role });

    } catch (err) {
        console.error(err);
        return res.json({ success: false, error: "Verification Error" });
    }
});

// RBAC Middleware
const requireRole = (allowedRoles) => (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: "Not Logged In" });
    if (!allowedRoles.includes(req.session.user.role)) return res.status(403).json({ error: "Access Denied" });
    next();
};

app.get("/api/profile", (req, res) => res.json(req.session.user || { error: "Not logged in" }));
app.get("/api/admin-data", requireRole(["admin"]), (req, res) => res.json({ data: "SECRET ADMIN DATA" }));
app.get("/api/editor-data", requireRole(["admin", "editor"]), (req, res) => res.json({ data: "EDITOR CONTENT" }));

app.listen(PORT, () => {
    console.log(`PKI Server running on http://localhost:${PORT}`);
});