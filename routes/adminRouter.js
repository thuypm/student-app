var express = require("express");
const authService = require("../service/authService");
var CONSTANT = require("../utils/constant");
var router = express.Router();

router.get("/", function (req, res, next) {
  res.render("admin", {
    WEEKDAY_COLUMNS: CONSTANT.WEEKDAY_COLUMNS,
    EVALUATE_COLUMNS: CONSTANT.EVALUATE_COLUMNS,
    ALL_STUDENTS: CONSTANT.ALL_STUDENTS,
    ALL_WEEKS: CONSTANT.ALL_WEEKS,
  });
});

router.post("/login", async function (req, res, next) {
  try {
    const { token } = await authService.login(req.body);
    res.status(200).json({
      token,
      success: true,
    });
  } catch (error) {
    res.status(400).json({
      message: "Invalid username or password",
    });
  }
});

module.exports = router;
