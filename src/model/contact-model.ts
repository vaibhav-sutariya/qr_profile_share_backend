import mongoose from "mongoose";
import crypto from "crypto";
import validator from "validator";
import User from "./user-model"; // assuming you are using it elsewhere, but not needed directly in schema

export interface IContact extends mongoose.Document {
	contactId: string;
	userId: String;
	name: string;
	email: string;
	phoneNumber: string;
	company: string;
	userRole: string;
	website: string;
	location: string;
	tags: string;
	socialLinks: {
		github: string;
		linkedIn: string;
		instagram: string;
		twitter: string;
	};
	photo: string;
	role: "user" | "admin";
	active: boolean;
	createdAt: Date;
	updatedAt: Date;
	createContactId: (id: string) => string;
}

const contactSchema = new mongoose.Schema<IContact>(
	{
		contactId: {
			type: String,
			required: true,
			unique: true,
		},
		userId: {
			type: String,
			required: true,
		},
		name: {
			type: String,
			required: true,
		},
		email: {
			type: String,
			required: true,
			validate: [validator.isEmail, "Please provide a valid email"],
		},
		phoneNumber: {
			type: String,
			required: [true, "Phone number is required."],
		},
		company: {
			type: String,
			required: true,
		},
		userRole: {
			type: String,
			required: true,
		},
		website: {
			type: String,
			default: "",
		},
		location: {
			type: String,
			required: true,
		},
		tags: {
			type: String,
			default: "",
		},
		socialLinks: {
			github: {
				type: String,
				default: "",
			},
			linkedIn: {
				type: String,
				default: "",
			},
			instagram: {
				type: String,
				default: "",
			},
			twitter: {
				type: String,
				default: "",
			},
		},
		photo: {
			type: String,
			default: "",
		},
		active: {
			type: Boolean,
			default: true,
			select: false,
		},
	},
	{
		timestamps: true,
	},
);

// Optional method to create a unique contactId
contactSchema.methods.createContactId = function (id: string) {
	return crypto.createHash("sha256").update(id).digest("hex");
};

const Contact = mongoose.model<IContact>("Contact", contactSchema);
export default Contact;
