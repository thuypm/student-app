import jwt, { TokenExpiredError } from "jsonwebtoken";
import createError from "http-errors";
import { AuthService } from "../service/authService";

export const authorization = (roles) => async (req, res, next) => {
  try {
    if (!req.headers || !req.headers.authorization) {
      throw createError(403, `Unauthorized token!`);
    }

    let token = req.headers.authorization;
    if (token.startsWith("Bearer ")) {
      token = token.substring(7, token.length);
    }

    const decode = jwt.verify(
      token,
      process.env.SECRET_KEY_JWT || "Amatrium#secretKey"
    );

    const check = AuthService.checkUser(decode);
    if (!check) {
      throw createError(401, "Unauthorized.");
    }
    req.user = decode;
    next();
  } catch (error) {
    if (error instanceof TokenExpiredError) {
      error.status = 401;
    }
    next(error);
  }
};
