const router = require("express").Router();
const controller = require("../controllers/auth.controller");

router.get("/challenge/:user", controller.challenge);
router.post("/verify", controller.verify);

module.exports = router;
