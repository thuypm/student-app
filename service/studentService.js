const studentModel = require("../models/studentModel");
const mongoose = require("mongoose");
class StudentService {
  model;
  constructor() {
    this.model = studentModel;
  }
  async searchOneStudentOneWeek({ studentId, week }) {
    try {
      const data = await this.model.findOne({
        studentId: studentId,
        week: week,
      });
      return data._doc;
    } catch (error) {
      throw error;
    }
  }
  async updateOneStudentOneWeek(body) {
    try {
      if (Array.isArray(body.point))
        return await this.model.findOneAndUpdate(
          {
            _id: mongoose.Types.ObjectId(body._id),
          },
          {
            $set: { point: body.point },
          }
        );
      throw new Error("Sai format");
    } catch (error) {
      throw error;
    }
  }
  async searchOneStudentAllWeek({ studentId }) {
    try {
      const data = await this.model.find({
        studentId: studentId,
        week: week,
      });
      return data;
    } catch (error) {
      throw error;
    }
  }

  async getAllData() {
    try {
      const data = await this.model.find({});
      return data;
    } catch (error) {
      throw error;
    }
  }
}

module.exports = new StudentService();
