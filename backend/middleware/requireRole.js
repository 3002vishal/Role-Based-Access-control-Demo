const { getRoleFromCert } = require("../services/cert.service");

const requireRole = (allowedRoles = []) => (req, res, next) => {
  const { username } = req.body;
  const role = getRoleFromCert(username);

  if (!role)
    return res.status(404).json({ error: "Role not found" });

  if (!allowedRoles.includes(role))
    return res.status(403).json({ error: "Access Denied" });

  next();
};

module.exports = requireRole;
