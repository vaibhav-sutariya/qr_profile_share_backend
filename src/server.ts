import app from "./app.js";
import dotenv from "dotenv";
import mongoose from "mongoose";
import path from "path";
import { fileURLToPath } from "url";
import admin from "firebase-admin";
import AwsS3Helper from "./utils/class/aws-s3-helper.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load the env file based on the current environment
const currentEnv = process.env.NODE_ENV || "development";
const envFile = path.join(__dirname, `./../.env.${currentEnv}`);

// env variables
dotenv.config({ path: envFile });

// iniitalize the firebase admin
const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/gm, "\n");
admin.initializeApp({
	credential: admin.credential.cert({
		projectId: process.env.FIREBASE_PROJECT_ID,
		clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
		privateKey: privateKey,
	}),
});

// initialize S3
AwsS3Helper.getInstance();

const DB: string = process.env.MONGO_DB?.replace(
	"<PASSWORD>",
	process.env.MONGO_DB_PASSWORD || "",
) as string;
mongoose
	.connect(DB, {
		dbName: "QrProfileShare",
	})
	.then(() => {
		// eslint-disable-next-line no-console
		console.log(`MongoDB connected successfully`);
	})
	.catch((err) => {
		// eslint-disable-next-line no-console
		console.log(err);
	});

const PORT = parseInt(process.env.PORT || "3000");
app.listen(PORT, "0.0.0.0", () => {
	// eslint-disable-next-line no-console
	console.log(`Server running on port ${PORT}`);
});
