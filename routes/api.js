var express = require("express");
const authService = require("../service/authService");
const studentService = require("../service/studentService");
var router = express.Router();

router.get("/", function (req, res, next) {
  res.send("Hello world");
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

router.get("/search", async function (req, res, next) {
  try {
    const data = await studentService.searchOneStudentOneWeek(req.query);
    res.status(200).json(data);
  } catch (error) {
    res.status(400).json({
      error: error,
    });
  }
});

router.post("/update", async function (req, res, next) {
  try {
    const data = await studentService.updateOneStudentOneWeek(req.body);
    res.status(200).json(data);
  } catch (error) {
    res.status(400).json({
      error: error,
    });
  }
});

module.exports = router;
