const path = require("path");

/**
 * Base paths
 * Adjust only if your demoCA or openssl.cnf moves
 */
const BASE_DIR = path.join(__dirname, "..");

const OPENSSL_CONFIG = path.join(BASE_DIR, "openssl.cnf");

const INTERMEDIATE_CA = {
  cert: path.join(BASE_DIR, "demoCA", "intermediate", "int.cert.pem"),
  key: path.join(
    BASE_DIR,
    "demoCA",
    "intermediate",
    "private",
    "int.key.pem"
  ),
};

/**
 * Returns the OpenSSL command used to sign a CSR
 */
function signCSRCommand({ csrPath, certPath, role }) {
  const ext =
    role === "admin"
      ? "role_admin"
      : role === "editor"
      ? "role_editor"
      : "role_viewer";

  return `
openssl x509 -req \
-in "${csrPath}" \
-CA "${INTERMEDIATE_CA.cert}" \
-CAkey "${INTERMEDIATE_CA.key}" \
-CAcreateserial \
-out "${certPath}" \
-days 365 \
-extfile "${OPENSSL_CONFIG}" \
-extensions ${ext}
`;
}

module.exports = {
  OPENSSL_CONFIG,
  INTERMEDIATE_CA,
  signCSRCommand,
};
