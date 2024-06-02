import User from "../models/user.model.js";

const generateAccessOrRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = await user.generateAccessToken();
        const refreshToken = await user.generateRefreshToken();

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: true });
        return { accessToken, refreshToken };
    } catch (error) {
        console.log(500, "somthing went wrong while generating refresh tokens");
    }
}

const generateRandomOtp = async () => {
   return Math.floor(100000 + Math.random() * 900000)
}

export {
    generateAccessOrRefreshTokens,
    generateRandomOtp
}