const router = require("express").Router();
const controller = require("../controllers/enroll.controller");

router.post("/enroll", controller.enroll);

module.exports = router;
