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
// --- ROUTE 2: SIGNUP (Enroll) ---
app.post('/signup', (req, res) => {
    const { username, role } = req.body;

    // 1. Validation
    if (!username || !role) {
        return res.status(400).json({ status: "error", message: "Username and Role are required" });
    }

    console.log(`[ENROLL] Starting enrollment for ${username} (${role})...`);

    // 2. Spawn PowerShell (signup.ps1)
    const ps = spawn('powershell.exe', [
        '-NoProfile', 
        '-ExecutionPolicy', 'Bypass', 
        '-File', path.join(__dirname, 'signup.ps1'), 
        '-username', username, 
        '-role', role
    ]);

    let scriptOutput = "";
    let scriptError = "";

    // 3. Capture Output (Stdout) - This includes BOTH logs and JSON
    ps.stdout.on('data', (data) => {
        scriptOutput += data.toString();
    });

    // 4. Capture Errors (Stderr)
    ps.stderr.on('data', (data) => {
        scriptError += data.toString();
    });

    // 5. Handle Process Close
    ps.on('close', (code) => {
        console.log(`[ENROLL] Process exited with code ${code}`);

        // If there was a hard crash (exit code 1 usually means your script "exit 1" ran)
        if (code !== 0) {
            console.error(`[ENROLL] Script Error Output: ${scriptError}`);
            // Even if it failed, we might have a JSON error message from PowerShell
            // So we still try to parse the output below, but if that fails, we return generic 500.
        }

        // 6. ROBUST JSON PARSING (The Fix)
        try {
            // Step A: Find the start of the JSON object (first curly brace)
            const jsonStartIndex = scriptOutput.indexOf('{');
            
            // Step B: If no JSON found, throw error
            if (jsonStartIndex === -1) {
                throw new Error("No JSON structure found in PowerShell output");
            }

            // Step C: Extract only the JSON part
            // This cuts off "[CLIENT] 1. Creating INF..."
            const cleanJsonString = scriptOutput.substring(jsonStartIndex);

            // Step D: Parse it
            const parsedResult = JSON.parse(cleanJsonString);
            
            console.log("[ENROLL] Parsed Success:", parsedResult.status);
            res.json(parsedResult);

        } catch (e) {
            console.error("[ENROLL] JSON Parse Logic Failed:", e.message);
            console.error("[ENROLL] Raw Output Was:\n", scriptOutput);
            
            res.status(500).json({ 
                status: "error", 
                message: "Bridge failed to parse PowerShell output", 
                details: scriptOutput // sending raw output helps you debug
            });
        }
    });
});
 
app.listen(PORT, () => {
    console.log(`HSM Bridge running on http://localhost:${PORT}`);
});