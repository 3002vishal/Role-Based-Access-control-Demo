import express from "express";
import { generateChallenge, verifySignature } from "./challenge.js";

const app = express();
app.use(express.json());

let challenges = {};  
// { username: "base64challenge" }

// ==========================================
// 1. SEND CHALLENGE TO USER
// ==========================================
app.get("/auth/challenge/:user", (req, res) => {
    const user = req.params.user;

    const challenge = generateChallenge();
    challenges[user] = challenge;

    res.json({ challenge });
});

// ==========================================
// 2. VERIFY SIGNATURE FROM USER
// ==========================================
app.post("/auth/verify", (req, res) => {
    const { username, signature } = req.body;

    if (!challenges[username]) {
        return res.status(400).json({ error: "No challenge for user." });
    }

    const challenge = challenges[username];

    try {
        const isValid = verifySignature(username, challenge, signature);

        if (!isValid) {
            return res.json({ success: false, msg: "Signature INVALID" });
        }

        // If valid, login successful
        delete challenges[username];

        return res.json({ success: true, msg: "User authenticated." });

    } catch (err) {
        return res.json({ success: false, error: err.message });
    }
});

// ==========================================
app.listen(5000, () => {
    console.log("Auth server running on http://localhost:5000");
});
