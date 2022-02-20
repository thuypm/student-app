const mongoose = require("mongoose");

const StudentSchema = new mongoose.Schema({
  studentId: {
    type: Number,
    default: null,
  },
  week: {
    type: Number,
    default: null,
  },
  point: {
    type: Array,
    default: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  },
});

module.exports = mongoose.model("thuys", StudentSchema);
