const jwt = require("jsonwebtoken");

const adminUser = {
  username: "admin",
  password: "Admin@1234",
};
class AuthService {
  async login(body) {
    const adminUser = {
      username: "admin",
      password: process.env.ADMIN_PASSWORD,
    };
    if (
      !body ||
      body.username !== adminUser.username ||
      body.password !== adminUser.password
    ) {
      throw new Error("Wrong email or password.");
    }

    const expiresIn = 60 * 60 * 24 * 30;
    const algorithm = process.env.JWT_ALGORITHM || "HS256";

    return {
      token: jwt.sign(
        {
          adminUser,
        },
        process.env.SECRET_KEY_JWT || "Amatrium#secretKey",
        {
          expiresIn,
          algorithm,
        }
      ),
    };
  }
  checkUser(body) {
    return (
      body.username !== adminUser.username ||
      body.password !== adminUser.password
    );
  }
}

module.exports = new AuthService();
