// File: bridge.js (ES Module Version)
import express from 'express';
import { spawn } from 'child_process';
import cors from 'cors';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
app.use(cors()); 
app.use(bodyParser.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;

// --- ROUTE 1: LOGIN (Sign Challenge) ---
app.post('/sign-challenge', (req, res) => {
    const challenge = req.body.challenge;
    if (!challenge) return res.status(400).json({ error: "No challenge provided" });

    console.log(`[SIGN] Launching Hardware Signer...`);

    const ps = spawn('powershell.exe', [
        '-NoProfile', '-ExecutionPolicy', 'Bypass', 
        '-File', path.join(__dirname, 'sign.ps1'), 
        '-ChallengeData', challenge
    ]);

    let signature = "";
    
    ps.stdout.on('data', (data) => { signature += data.toString().trim(); });
    ps.on('close', (code) => {
        if (code !== 0 || signature.includes("ERROR")) {
            console.error("[SIGN] Failed");
            return res.status(500).json({ error: "Signing Failed", details: signature });
        }
        res.json({ status: "success", signature: signature });
    });
});

 
app.listen(PORT, () => {
    console.log(`HSM Bridge running on http://localhost:${PORT}`);
});