from flask import Flask, request, jsonify, g
import subprocess
import os
import OpenSSL.crypto as crypto
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import secrets
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# -------------------------
# Database setup
# -------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///certs.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class UserCert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)
    cert_path = db.Column(db.String(200), nullable=False)


with app.app_context():
    db.create_all()

# -------------------------
# Config
# -------------------------
PS_SCRIPT_PATH = r"..\openssl\issue_cert.ps1"

# Create cert directory inside current working directory
CERT_DIR = os.path.join(os.getcwd(), "cert")
os.makedirs(CERT_DIR, exist_ok=True)

ALLOWED_ROLES = ["admin", "viewer", "editor"]

# In-memory stores
SESSIONS = {}       # token → {username, role}
CHALLENGES = {}     # username → challenge


# -------------------------
# Helper: role-based access
# -------------------------
def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization")
            if not token or token not in SESSIONS:
                return jsonify({"error": "Unauthorized"}), 401

            user = SESSIONS[token]
            if user["role"] not in allowed_roles:
                return jsonify({"error": "Forbidden: insufficient role"}), 403

            g.user = user
            return f(*args, **kwargs)
        return wrapper
    return decorator


# -------------------------
# Enroll route
# -------------------------
@app.route("/enroll", methods=["POST"])
def enroll():
    data = request.json
    username = data.get("username")
    role = data.get("role")
    type_ = "client"

    if not username or not role:
        return jsonify({"error": "username and role required"}), 400
    if role not in ALLOWED_ROLES:
        return jsonify({"error": "role not allowed"}), 403

    # Run PowerShell script to issue cert
    cmd = [
        "powershell.exe",
        "-ExecutionPolicy", "Bypass",
        "-File", PS_SCRIPT_PATH,
        "-CN", username,
        "-ROLE", role,
        "-TYPE", type_
    ]

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Failed to issue certificate", "details": str(e)}), 500

    # Store cert in ./cert/username.cert.pem
    cert_file = os.path.join(CERT_DIR, f"{username}.cert.pem")

    # Save in DB (no private key storage)
    user_cert = UserCert.query.filter_by(username=username).first()
    if user_cert:
        user_cert.cert_path = cert_file
        user_cert.role = role
    else:
        user_cert = UserCert(username=username, role=role, cert_path=cert_file)
        db.session.add(user_cert)
    db.session.commit()

    return jsonify({
        "cert_file": cert_file,
        "role": role,
        "type": type_
    })


# -------------------------
# Login Step 1: Issue challenge
# -------------------------
@app.route("/login-challenge", methods=["POST"])
def login_challenge():
    data = request.json
    username = data.get("username")
    if not username:
        return jsonify({"error": "username required"}), 400

    db_user = UserCert.query.filter_by(username=username).first()
    if not db_user:
        return jsonify({"error": "User not enrolled"}), 404

    # Generate random challenge
    challenge = secrets.token_bytes(32)
    challenge_b64 = base64.b64encode(challenge).decode()

    CHALLENGES[username] = challenge

    return jsonify({"challenge": challenge_b64})


# -------------------------
# Login Step 2: Verify signature
# -------------------------
@app.route("/login-verify", methods=["POST"])
def login_verify():
    data = request.json
    username = data.get("username")
    signature_b64 = data.get("signature")

    if not username or not signature_b64:
        return jsonify({"error": "username and signature required"}), 400

    db_user = UserCert.query.filter_by(username=username).first()
    if not db_user:
        return jsonify({"error": "User not enrolled"}), 404

    # Load stored certificate
    with open(db_user.cert_path, "rb") as f:
        cert_data = f.read()
        user_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

    # Extract public key as cryptography object
    pub_key = load_pem_public_key(
        crypto.dump_publickey(crypto.FILETYPE_PEM, user_cert.get_pubkey())
    )

    # Get challenge
    challenge = CHALLENGES.get(username)
    if not challenge:
        return jsonify({"error": "No challenge found for user"}), 400

    signature = base64.b64decode(signature_b64)

    try:
        pub_key.verify(
            signature,
            challenge,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # If successful, issue session token
        token = f"{username}-{secrets.token_hex(16)}"
        SESSIONS[token] = {"username": username, "role": db_user.role}
        del CHALLENGES[username]

        return jsonify({
            "message": "Login successful",
            "username": username,
            "role": db_user.role,
            "token": token
        })
    except Exception as e:
        return jsonify({"error": "Signature verification failed", "details": str(e)}), 401


# -------------------------
# Role-based routes
# -------------------------
@app.route("/admin-data")
@role_required(["admin"])
def admin_data():
    return jsonify({"message": f"Welcome Admin {g.user['username']}!"})


@app.route("/viewer-data")
@role_required(["viewer", "admin"])
def viewer_data():
    return jsonify({"message": f"Hello {g.user['username']}, you can view data."})


@app.route("/editor-data")
@role_required(["editor", "admin"])
def editor_data():
    return jsonify({"message": f"Hello {g.user['username']}, you can edit data."})


# -------------------------
# Main entry
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
