import mongoose, { Schema } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const userSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
            index: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
            index: true,
        },
        password: {
            type: String,
            required: [true, "password is required"]
        },
        profilePicture: {
            type: String,
            default: "https://png.pngtree.com/png-clipart/20210915/ourlarge/pngtree-user-avatar-login-interface-abstract-purple-user-icon-png-image_3917506.jpg"
        },
        isAdmin: {
            type: Boolean,
            default: false,
        },
        refreshToken: {
            type: String,
        },
    },
    { timestamps: true }
)


userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password, 10)
    next()
})

userSchema.methods.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password, this.password);
}

userSchema.methods.generateAccessToken = async function () {
    return jwt.sign(
        {
            _id: this._id,
            username: this.username,
            email: this.email
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: process.env.ACCESS_TOKEN_EXPIRY || "1d"}
    )
}

userSchema.methods.generateRefreshToken = async function () {
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: process.env.REFRESH_TOKEN_EXPIRY || "10d"}
    )
}

userSchema.methods.generateResetPasswordToken = async function () {
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.PASSWORD_RESET_TOKEN,
        { expiresIn: "10m" }
    )
}

const User = mongoose.model("User", userSchema);

export default User;