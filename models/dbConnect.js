const mongoose = require("mongoose");
async function dbConnect() {
  try {
    await mongoose.connect(
      process.env.MONGO_URL ||
        "mongodb+srv://thuypm:thuypm@cluster0.3sy8z.mongodb.net/student",
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }
    );
    console.log("connected db");
    return mongoose;
  } catch (error) {
    console.log(error);
  }
}
module.exports = dbConnect;
