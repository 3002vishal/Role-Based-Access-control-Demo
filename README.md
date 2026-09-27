# Certificate-Based Role Access Control Demo

A Flask-based proof of concept for **PKI-backed authentication and role-based authorization**.

## Authentication Model

Instead of authenticating only with a reusable password or bearer token, the application issues a random challenge that must be signed with the user's private key. The server verifies the signature using the public key contained in the user's X.509 certificate.

```text
User -> request login challenge
Server -> random challenge
User -> signs challenge with private key
Server -> verifies signature using certificate
Server -> creates authenticated session
Session -> checked against role-protected endpoint
```

## Roles

The demo includes:
- `admin`
- `viewer`
- `editor`

Protected routes enforce role requirements after certificate-backed authentication.

## Tech Stack

- Python
- Flask
- Flask-SQLAlchemy
- SQLite
- PyOpenSSL
- cryptography
- OpenSSL / PowerShell certificate scripts
- X.509 / PKI

## Security

Private keys and CA signing keys are excluded from the active branch. Generate fresh local development keys before running this project.

Any key previously committed publicly must be treated as compromised and rotated.

## Purpose

This project demonstrates the difference between **identity proof through private-key possession** and subsequent **role-based authorization**.
