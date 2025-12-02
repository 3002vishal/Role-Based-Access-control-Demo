// File: bridge.js (ES Module Version)
import express from 'express';
import { spawn } from 'child_process';
import cors from 'cors';
import bodyParser from 'body-parser';

const app = express();
app.use(cors()); 
app.use(bodyParser.json());

const PORT = 3000;

app.post('/sign-challenge', (req, res) => {
    const challenge = req.body.challenge;
    
    if (!challenge) {
        return res.status(400).json({ error: "No challenge provided" });
    }

    console.log(`Received challenge: ${challenge}. Launching Hardware Signer...`);

    // Spawn PowerShell as a child process
    const ps = spawn('powershell.exe', [
        '-NoProfile', 
        '-ExecutionPolicy', 'Bypass', 
        '-File', './sign.ps1', 
        '-Challenge', challenge
    ]);

    let signature = "";
    let errorOutput = "";

    ps.stdout.on('data', (data) => {
        signature += data.toString().trim();
    });

    ps.stderr.on('data', (data) => {
        errorOutput += data.toString();
    });

    ps.on('close', (code) => {
        if (code !== 0 || signature.startsWith("ERROR")) {
            console.error("Signing Failed:", signature || errorOutput);
            return res.status(500).json({ error: "Signing Failed", details: signature });
        }
        
        console.log("Success! Signature sent to browser.");
        res.json({ 
            status: "success", 
            signature: signature 
        });
    });
});

app.listen(PORT, () => {
    console.log(`HSM Bridge running on http://localhost:${PORT}`);
});