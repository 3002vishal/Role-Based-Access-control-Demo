const router = require("express").Router();
const requireRole = require("../middleware/requireRole");

router.post("/admin-data", requireRole(["admin"]), (req, res) =>
  res.json({ data: "ADMIN DATA" })
);

router.post("/editor-data", requireRole(["editor", "admin"]), (req, res) =>
  res.json({ data: "EDITOR DATA" })
);

router.post("/viewer-data", requireRole(["viewer", "editor", "admin"]), (req, res) =>
  res.json({ data: "VIEWER DATA" })
);

module.exports = router;
