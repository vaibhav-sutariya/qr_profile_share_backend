import mongoose from "mongoose";
import crypto from "crypto";

export interface IRefreshToken extends mongoose.Document {
	refreshToken: string;
	userId: string;
	expiresAt: Date;
	createRefreshToken: (token: string) => string;
}

const refreshTokenSchema = new mongoose.Schema<IRefreshToken>({
	refreshToken: {
		type: String,
		required: [true, "Please add a refresh token"],
		unique: false,
		select: false,
	},
	userId: {
		type: String,
		required: true,
		ref: "User",
	},
	expiresAt: {
		type: Date,
		default: Date.now() + 7 * 24 * 60 * 60 * 1000,
		expires: "7d",
	},
});

/**
 * Creates a refresh token by hashing the given token using the SHA-256 algorithm.
 *
 * @param {string} token - The token to be hashed.
 * @return {string} The refresh token.
 */
refreshTokenSchema.methods.createRefreshToken = function (
	token: string,
): string {
	const refreshToken = crypto
		.createHash("sha256")
		.update(token)
		.digest("hex");

	return refreshToken;
};

const RefreshToken = mongoose.model<IRefreshToken>(
	"RefreshToken",
	refreshTokenSchema,
);

export default RefreshToken;
