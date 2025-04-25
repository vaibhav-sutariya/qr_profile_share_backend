import nodemailerSendgrid from "nodemailer-sendgrid";
import modemailer, { TransportOptions } from "nodemailer";
import { IUser } from "../model/user-model.js";
import path from "path";
import { fileURLToPath } from "url";
import ejs from "ejs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default class Email {
	to: string;
	firstName: string;
	url: string;
	from: string;
	subject?: string;
	expiresIn?: string;

	constructor(user: IUser, url: string, expiresIn?: string) {
		(this.to = user.email), (this.firstName = user.name.split("")[0]);
		this.url = url;
		this.from =
			process.env.EMAIL_FROM ||
			"Vaibhav Sutariya <vsutariya428@gmail.com>";
		this.expiresIn = expiresIn;
	}

	createNewTransport() {
		if (process.env.NODE_ENV === "production") {
			return modemailer.createTransport(
				nodemailerSendgrid({
					apiKey: process.env.SENDGRID_API_KEY || "",
				}),
			);
		}

		return modemailer.createTransport({
			host: process.env.EMAIL_HOST,
			port: process.env.EMAIL_PORT,
			authMethod: "LOGIN",
			secure: false,
			auth: {
				user: process.env.EMAIL_USERNAME,
				pass: process.env.EMAIL_PASSWORD,
			},
		} as TransportOptions);
	}

	async send(template: string, subject: string) {
		const emailPath = path.join(
			__dirname,
			"../view/email/",
			`${template}.ejs`,
		);

		const html = await ejs.renderFile(
			emailPath,
			{
				firstName: this.firstName,
				url: this.url,
				expiresIn: this.expiresIn,
			},
			{
				async: true,
			},
		);

		const mailOptions = {
			from: this.from,
			to: this.to,
			subject,
			html: html,
		};
		await this.createNewTransport().sendMail(mailOptions);
	}

	async sendVerifyEmail() {
		await this.send(
			"verifyEmail",
			"QrProfileShare: Verify your email address",
		);
	}

	async sendWelcomeEmail() {
		await this.send("welcome", "QrProfileShare: Welcome to QrProfileShare");
	}

	async sendPasswordResetEmail() {
		await this.send(
			"passwordResetEmail",
			"QrProfileShare: Reset your password",
		);
	}
}
