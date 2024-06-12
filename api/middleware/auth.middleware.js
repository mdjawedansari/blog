
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"
import { errorHandler } from "../utils/ApiError.js";
import User from "../models/user.model.js";

const authenticatedUser = asyncHandler(async (req, res, next) => {
    try { 
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
        if (!token) {
            return next(errorHandler(401, "unauthorized request"));
        }
        const decodedToken = await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        const user = await User.findById(decodedToken?._id).select(
            "-password -refreshToken"
        )

        if (!user) {
            return next( errorHandler(401, "invalid token"));
        }

        req.user = user;
        next()
    } catch (error) {
        return next(errorHandler(401, error || "token expired"));
    }
})

const isAdmin = asyncHandler(async (req, res, next) => {
    try { 
        const { email } = req.user;
        const adminUser = await User.findOne({ email })
        if (adminUser?.role !== "admin") {
            return next(errorHandler(400, "you dont have access ☠️"))
        }

        next()

    } catch (error) {
        return next(errorHandler(401, error || "Invalid user"));
    }
})

export { authenticatedUser, isAdmin }