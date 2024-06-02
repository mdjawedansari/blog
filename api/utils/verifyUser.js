import jwt from "jsonwebtoken";
import { errorHandler } from "./error.js";
import User from "../models/user.model.js";

export const verifyToken = async (req, _, next) => {
  try {
    const token =
      req.cookies?.accessToken ||
      req.header("Authorization")?.replace("Bearer ", "");
    if (!token) {
      return next(errorHandler(401, "Unauthorized"));
    }
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    );
    if (!user) {
      return next(errorHandler(401, "invalid token"));
    }
    req.user = user;
    next();
  } catch (error) {
    return next(errorHandler(401, error || "token expired"));
  }
};
