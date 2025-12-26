const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { CERT_DIR } = require("../config");
const {
  createChallenge,
  consumeChallenge,
} = require("../services/challenge.service");
const { getRoleFromCert } = require("../services/cert.service");

exports.challenge = (req, res) => {
  const challenge = createChallenge(req.params.user);
  res.json({ challenge });
};

exports.verify = (req, res) => {
  const { username, signature } = req.body;
  const challenge = consumeChallenge(username);

  if (!challenge)
    return res.status(400).json({ error: "No challenge" });

  const certPath = path.join(CERT_DIR, `${username}_cert.pem`);
  const certPem = fs.readFileSync(certPath, "utf8");

  const publicKey = crypto.createPublicKey(certPem);
  const isValid = crypto.verify(
    "sha256",
    Buffer.from(challenge),
    publicKey,
    Buffer.from(signature, "base64")
  );

  if (!isValid)
    return res.status(403).json({ success: false });

  res.json({ success: true, role: getRoleFromCert(username) });
};
