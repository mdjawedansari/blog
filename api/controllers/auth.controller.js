import { generateAccessOrRefreshTokens } from "../helper/tokenHelper.js";
import User from "../models/user.model.js";
import { errorHandler } from "../utils/error.js";

// Register user
export const signup = async (req, res, next) => {
  const { username, email, password } = req.body;
  if ([username, email, password].some((field) => field.trim() === "")) {
    return next(errorHandler(400, "All fields are required"));
  }

  const isExistingUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (isExistingUser) {
    return next(errorHandler(400, "User already exists, please sign in"));
  }

  const user = await User.create({
    username: username.toLowerCase(),
    email,
    password,
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    return next(
      errorHandler(500, "Something went wrong while registering user")
    );
  }

  return res.status(200).json(createdUser);
};

// Login user
export const signin = async (req, res, next) => {
  const { email, password } = req.body;
  if ([email, password].some((field) => field.trim() === "")) {
    return next(errorHandler(400, "Email and password are required"));
  }

  const user = await User.findOne({email});

  if (!user) {
    return next(errorHandler(400, "User not found"));
  }

  const isPasswordCorrect = await user.isPasswordCorrect(password);

  if (!isPasswordCorrect) {
    return next(errorHandler(400, "Invalid credentials"));
  }

  const { accessToken, refreshToken } = await generateAccessOrRefreshTokens(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken -accessToken -__v"
  );

  const accessOptions = {
    httpOnly: true,
    secure: true,
    maxAge: 24 * 60 * 60 * 1000,
  };

  const refreshOptions = {
    httpOnly: true,
    secure: true,
    maxAge: 72 * 60 * 60 * 1000,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, accessOptions)
    .cookie("refreshToken", refreshToken, refreshOptions)
    .json(loggedInUser);
};
