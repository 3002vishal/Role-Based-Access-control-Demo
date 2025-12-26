const fs = require("fs");
const path = require("path");
const forge = require("node-forge");
const { CERT_DIR } = require("../config");

function getRoleFromCert(username) {
  try {
    const certPath = path.join(CERT_DIR, `${username}_cert.pem`);
    if (!fs.existsSync(certPath)) return null;

    const certPem = fs.readFileSync(certPath, "utf8");
    const cert = forge.pki.certificateFromPem(certPem);

    const roleExt = cert.extensions.find(
      (ext) => ext.id === "1.2.3.4.5.6.7.8.1"
    );

    if (!roleExt?.value) return "viewer";

    const value = roleExt.value.toString().toLowerCase();

    if (value.includes("admin")) return "admin";
    if (value.includes("editor")) return "editor";
    return "viewer";
  } catch {
    return null;
  }
}

module.exports = { getRoleFromCert };
