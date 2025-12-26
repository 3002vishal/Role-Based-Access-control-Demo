const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const { CERT_DIR } = require("../config");
const { signCSRCommand } = require("../config/openssl");

exports.enroll = (req, res) => {
  const { username, csr, role } = req.body;

  const csrPath = path.join(CERT_DIR, `${username}_req.csr`);
  const certPath = path.join(CERT_DIR, `${username}_cert.pem`);

  fs.writeFileSync(csrPath, Array.isArray(csr) ? csr.join("\n") : csr);

  const cmd = signCSRCommand({
    csrPath,
    certPath,
    role,
  });

  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      console.error("OpenSSL error:", stderr);
      return res.status(500).json({ error: "Certificate signing failed" });
    }

    const certificate = fs.readFileSync(certPath, "utf8");
    fs.unlinkSync(csrPath);

    res.json({ success: true, certificate });
  });
};
