import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import validator from "validator";

export enum AuthType {
	email = "email",
	social = "social",
	phone = "phone",
}

export enum UserRole {
	user = "user",
	admin = "admin",
}

export interface ISocialLinks {
	github: string;
	linkediIn: string;
	instagram: string;
	twitter: string;
}

export interface IUser extends mongoose.Document {
	name: string;
	email: string;
	photo: string;
	role: string;
	password: string;
	passwordConfirm?: string;
	passwordChangedAt?: Date;
	passwordResetToken?: string;
	passwordResetExpires?: Date;
	verifyEmailToken?: string;
	verifyEmailExpires?: Date;
	authType?: AuthType;
	phoneNumber?: string;
	location?: string;
	company?: string;
	website?: string;
	socialLinks: ISocialLinks;
	scans?: number;
	userRole?: String;
	active: boolean;
	emailVerified: boolean;
	createdAt: Date;
	updatedAt: Date;
	createVerifyEmailToken: () => string;
	createPasswordResetToken: () => string;
	checkPassword: (hash: string, userPassword: string) => Promise<boolean>;
	changedPasswordAfter: (JWTTimeStamp: number) => boolean;
	comparePassword: (
		password: string,
		passwordHash: string,
	) => Promise<boolean>;
}

const userSchema = new mongoose.Schema<IUser>(
	{
		name: {
			type: String,
			required: [true, "Please add a name"],
			// unique: true,
			maxlength: [50, "Name can not be more than 50 characters"],
			minlength: [4, "Name can not be less than 3 characters"],
		},
		email: {
			type: String,
			required: [true, "Please add an email"],
			unique: true,
			lowercase: true,
			validate: [validator.isEmail, "Please provide a valid email"],
		},
		phoneNumber: {
			type: String,
			unique: true,
			required: false,
			sparse: true,
		},
		photo: {
			type: String,
			default: "default.jpg",
		},
		role: {
			type: String,
			enum: UserRole,
			default: "user",
		},
		password: {
			type: String,
			required: [true, "Please add a password"],
			minlength: [8, "Password must be at least 8 characters"],
			maxlength: [20, "Password can not be more than 20 characters"],
			select: false,
		},
		passwordConfirm: {
			type: String,
			required: [true, "Please add a confirm password"],
			validate: {
				validator(this: IUser, passwordConfirm: string) {
					return passwordConfirm === this.password;
				},
				message: "Passwords do not match",
			},
		},
		emailVerified: {
			type: Boolean,
			default: false,
		},
		authType: {
			type: String,
			enum: AuthType,
		},
		active: {
			type: Boolean,
			default: true,
		},
		location: {
			type: String,
			required: false,
		},
		company: {
			type: String,
			required: false,
		},
		website: {
			type: String,
			required: false,
		},
		userRole: {
			type: String,
			required: false,
		},
		socialLinks: {
			github: {
				type: String,
				required: false,
				default: "",
			},
			linkedIn: {
				type: String,
				required: false,
				default: "",
			},
			instagram: {
				type: String,
				required: false,
				default: "",
			},
			twitter: {
				type: String,
				required: false,
				default: "",
			},
		},
		scans: {
			type: Number,
			default: 0,
		},
		passwordChangedAt: Date,
		passwordResetToken: String,
		passwordResetExpires: Date,
		verifyEmailToken: String,
		verifyEmailExpires: Date,
	},
	{
		timestamps: true,
	},
);

// pre hook middleware - run before save and create
// function to encrypt the password
userSchema.pre("save", async function (next) {
	// only run this function if the password was actually modified
	if (!this.isModified("password")) return next();
	if (!this.password) return next();
	// hash the password witht eh salt of 12
	this.password = await bcrypt.hash(this.password, 12);
	// delete the passwordConfirm field
	this.passwordConfirm = undefined;
	// next middleware
	next();
});

// pre hook middleware - run before save and create
// function to udate the passwordChangedAt field
// only run this function if the password was actually modified
userSchema.pre("save", function (next) {
	// only run this function if the password was actually modified
	// The 'isModified' method is used for checking if a certain field is modified since being loaded in from the database.
	// The 'isNew' property is a boolean indicating whether this document was just created.
	// If the 'password' field on 'this' instance wasn't changed, or if the document is new,
	// the function immediately calls 'next' and ends
	if (!this.isModified("password") || this.isNew) return next();
	this.passwordChangedAt = new Date(Date.now() - 1000);
	next();
});

/**
 * Generates a token for email verification.
 *
 * @return {string} The generated email verification token.
 */
userSchema.methods.createVerifyEmailToken = function (): string {
	// generate a token 32 bytes. It is then converted to a hexadecimal string
	const token = crypto.randomBytes(32).toString("hex");
	// store the token in the database
	// encrypt the token witht he SHA-256 hashing algorithm
	this.verifyEmailToken = crypto
		.createHash("sha256")
		.update(token)
		.digest("hex");
	// set the expires time to 1 day or 24 hrs
	// verify token will expire in 24 hrs
	this.verifyEmailExpires = Date.now() + 60 * 60 * 1000 * 24;
	// return the token
	return token;
};

/**
 * Generates a password reset token for the user.
 *
 * @return {string} The generated password reset token.
 */
userSchema.methods.createPasswordResetToken = function (): string {
	// generate a token 32 bytes. It is then converted to a hexadecimal string
	const token = crypto.randomBytes(32).toString("hex");
	// store the token in the database
	// encrypt the token witht he SHA-256 hashing algorithm
	this.passwordResetToken = crypto
		.createHash("sha256")
		.update(token)
		.digest("hex");
	// set the expires time to 10 mins
	// verify token will expire in 10 mins
	this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
	// return the token
	return token;
};

/**
 * Checks if the provided password matches the hashed password stored in the user schema.
 *
 * @param {string} hash - The hashed password to compare against.
 * @param {string} userPassword - The password to be checked.
 * @return {Promise<boolean>} A promise that resolves to a boolean indicating whether the passwords match.
 */
userSchema.methods.checkPassword = async function (
	hash: string,
	userPassword: string,
): Promise<boolean> {
	return await bcrypt.compare(userPassword, hash);
};

/**
 * Checks if the password has been changed after the given JWT token timestamp.
 *
 * @param {number} JWTTokenTimeStamp - The timestamp of the JWT token.
 * @return {boolean} Returns true if the password has been changed after the given timestamp, false otherwise.
 */
userSchema.methods.changedPasswordAfter = function (
	this: IUser,
	JWTTokenTimeStamp: number,
): boolean {
	if (this.passwordChangedAt) {
		const changedTimeStamp = this.passwordChangedAt.getTime() / 1000;
		return JWTTokenTimeStamp < changedTimeStamp;
	}

	return false;
};

/**
 * Compares a provided password with a hashed password and returns a Promise that resolves to a boolean indicating whether the passwords match.
 *
 * @param {string} password - The password to be checked.
 * @param {string} passwordHash - The hashed password to compare against.
 * @return {Promise<boolean>} A Promise that resolves to a boolean indicating whether the passwords match.
 */
userSchema.methods.comparePassword = async function (
	password: string,
	passwordHash: string,
): Promise<boolean> {
	return bcrypt.compare(password, passwordHash);
};

const User = mongoose.model<IUser>("User", userSchema, "users");

export default User;
