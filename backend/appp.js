const express = require('express');
const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { promisify } = require('util');

const app = express();
app.use(cors());
app.use(express.json());

// -------------------------
// Database setup
// -------------------------
const db = new sqlite3.Database('./certs.db');

// Promisify database methods
const dbRun = promisify(db.run.bind(db));
const dbGet = promisify(db.get.bind(db));
const dbAll = promisify(db.all.bind(db));

// Initialize database
async function initDB() {
    await dbRun(`
        CREATE TABLE IF NOT EXISTS user_certs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            cert_path TEXT NOT NULL
        )
    `);
}

initDB().catch(console.error);

// -------------------------
// Config
// -------------------------
const PS_SCRIPT_PATH = path.join('..', 'openssl', 'issue_cert.ps1');
const BASE_DIR = process.cwd();
const CERT_DIR = path.join(BASE_DIR, 'cert');

// Ensure cert directory exists
fs.mkdir(CERT_DIR, { recursive: true }).catch(console.error);

const ALLOWED_ROLES = ['admin', 'viewer', 'editor'];

// JWT config
const JWT_SECRET = crypto.randomBytes(32).toString('hex');
const JWT_ALGORITHM = 'HS256';
const JWT_EXP_DELTA_SECONDS = 3600; // 1 hour expiry

// In-memory store for challenges
const CHALLENGES = {}; // username → challenge

// -------------------------
// Helper: role-based access middleware
// -------------------------
function roleRequired(allowedRoles) {
    return async (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const token = authHeader.split(' ')[1];
        try {
            const payload = jwt.verify(token, JWT_SECRET, { algorithm: JWT_ALGORITHM });
            
            if (!allowedRoles.includes(payload.role)) {
                return res.status(403).json({ error: 'Forbidden: insufficient role' });
            }

            req.user = { username: payload.username, role: payload.role };
            next();
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({ error: 'Token expired' });
            }
            return res.status(401).json({ error: 'Invalid token' });
        }
    };
}

// -------------------------
// Helper: Execute PowerShell command
// -------------------------
function executePowerShell(scriptPath, args) {
    return new Promise((resolve, reject) => {
        const cmd = `powershell.exe -ExecutionPolicy Bypass -File "${scriptPath}" ${args.join(' ')}`;
        exec(cmd, (error, stdout, stderr) => {
            if (error) {
                reject(error);
            } else {
                resolve({ stdout, stderr });
            }
        });
    });
}

// -------------------------
// Enroll route
// -------------------------
app.post('/enroll', async (req, res) => {
    try {
        const { username, role } = req.body;
        const type = 'client';

        if (!username || !role) {
            return res.status(400).json({ error: 'username and role required' });
        }

        if (!ALLOWED_ROLES.includes(role)) {
            return res.status(403).json({ error: 'role not allowed' });
        }

        const args = [
            '-CN', username,
            '-ROLE', role,
            '-TYPE', type,
            '-OUTDIR', CERT_DIR
        ];

        await executePowerShell(PS_SCRIPT_PATH, args);

        const certFile = path.join(CERT_DIR, `${username}.cert.pem`);
        const keyFile = path.join(CERT_DIR, `${username}.key.pem`);

        // Save cert info in DB (no private key!)
        const existingUser = await dbGet('SELECT * FROM user_certs WHERE username = ?', [username]);
        
        if (existingUser) {
            await dbRun('UPDATE user_certs SET cert_path = ?, role = ? WHERE username = ?', 
                       [certFile, role, username]);
        } else {
            await dbRun('INSERT INTO user_certs (username, role, cert_path) VALUES (?, ?, ?)', 
                       [username, role, certFile]);
        }

        // Read private key (only once)
        const keyContent = await fs.readFile(keyFile);

        // Delete private key file from server
        try {
            await fs.unlink(keyFile);
        } catch (error) {
            console.warn('Failed to delete private key file:', error.message);
        }

        // Return private key as base64 string
        res.json({
            username,
            role,
            type,
            private_key_b64: keyContent.toString('base64')
        });

    } catch (error) {
        console.error('Enrollment error:', error);
        res.status(500).json({ 
            error: 'Failed to issue certificate', 
            details: error.message 
        });
    }
});

// -------------------------
// Login Step 1: Issue challenge
// -------------------------
app.post('/login-challenge', async (req, res) => {
    try {
        const { username } = req.body;
        if (!username) {
            return res.status(400).json({ error: 'username required' });
        }

        const dbUser = await dbGet('SELECT * FROM user_certs WHERE username = ?', [username]);
        if (!dbUser) {
            return res.status(404).json({ error: 'User not enrolled' });
        }

        // Generate random challenge
        const challenge = crypto.randomBytes(32);
        const challengeB64 = challenge.toString('base64');
        CHALLENGES[username] = challenge;

        res.json({ challenge: challengeB64 });

    } catch (error) {
        console.error('Challenge error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// -------------------------
// Login Step 2: Verify signature and issue JWT
// -------------------------
app.post('/login-verify', async (req, res) => {
    try {
        const { username, signature: signatureB64 } = req.body;

        if (!username || !signatureB64) {
            return res.status(400).json({ error: 'username and signature required' });
        }

        const dbUser = await dbGet('SELECT * FROM user_certs WHERE username = ?', [username]);
        if (!dbUser) {
            return res.status(404).json({ error: 'User not enrolled' });
        }

        // Load stored certificate
        const certData = await fs.readFile(dbUser.cert_path);
        
        // Extract public key from certificate
        const cert = new crypto.X509Certificate(certData);
        const publicKey = cert.publicKey;

        const challenge = CHALLENGES[username];
        if (!challenge) {
            return res.status(400).json({ error: 'No challenge found for user' });
        }

        const signature = Buffer.from(signatureB64, 'base64');

        // Verify signature
        const verify = crypto.createVerify('SHA256');
        verify.update(challenge);
        const isValid = verify.verify(publicKey, signature);

        if (!isValid) {
            return res.status(401).json({ error: 'Signature verification failed' });
        }

        // JWT payload
        const payload = {
            username,
            role: dbUser.role,
            exp: Math.floor(Date.now() / 1000) + JWT_EXP_DELTA_SECONDS
        };

        const token = jwt.sign(payload, JWT_SECRET, { algorithm: JWT_ALGORITHM });
        delete CHALLENGES[username];

        res.json({
            message: 'Login successful',
            username,
            role: dbUser.role,
            token
        });

    } catch (error) {
        console.error('Verification error:', error);
        res.status(401).json({ 
            error: 'Signature verification failed', 
            details: error.message 
        });
    }
});

// -------------------------
// Role-based routes
// -------------------------
app.get('/admin-data', roleRequired(['admin']), (req, res) => {
    res.json({ message: `Welcome Admin ${req.user.username}!` });
});

app.get('/viewer-data', roleRequired(['viewer', 'admin']), (req, res) => {
    res.json({ message: `Hello ${req.user.username}, you can view data.` });
});

app.get('/editor-data', roleRequired(['editor', 'admin']), (req, res) => {
    res.json({ message: `Hello ${req.user.username}, you can edit data.` });
});

// ------------------------- 
// Error handling middleware
// -------------------------
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// -------------------------
// Start server
// -------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('Shutting down gracefully...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});  