import express, { NextFunction, Request, Response } from "express";
import userRouter from "./route/user-routes.js";
import authRouter from "./route/auth-routes.js";
import adminRouter from "./route/admin-routes.js";
import homeRouter from "./route/home-routes.js";
import contactRouter from "./route/contact-routes.js";
import AppError from "./utils/app-error.js";
import globalErrorHandler from "./utils/global-error-handler.js";
import HttpStatusCode from "./utils/http-status-code.js";
import cookieParser from "cookie-parser";
import cors, { CorsOptions } from "cors";
import path from "path";
import { fileURLToPath } from "url";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import mongoSanitize from "express-mongo-sanitize";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const payload = {};

const app = express();

app.set("trust proxy", 1);

// global rate limit
const globalRateLimit = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes - How long to remember requests for, in milliseconds.
	max: 50, // How many requests to allow.
	standardHeaders: "draft-7", // Enable the Ratelimit header.
	legacyHeaders: false,
	// Function to run after limit is reached (overrides message and statusCode settings, if set).
	handler: (req: Request, res: Response, next: NextFunction) => {
		next(
			new AppError(
				"Too many requests, please try again later.",
				HttpStatusCode.TOO_MANY_REQUESTS,
			),
		);
	},
});

// Auth rate limit
const authRateLimit = rateLimit({
	windowMs: 5 * 60 * 1000, // 5 minutes - How long to remember requests for, in milliseconds.
	max: 10, // How many requests to allow.
	standardHeaders: "draft-7", // Enable the Ratelimit header.
	legacyHeaders: false,
	// Function to run after limit is reached (overrides message and statusCode settings, if set).
	handler: (req: Request, res: Response, next: NextFunction) => {
		next(
			new AppError(
				"Too many requests, please try again later.",
				HttpStatusCode.TOO_MANY_REQUESTS,
			),
		);
	},
});
const corsOptions: CorsOptions = {
	origin: function (
		origin: string | undefined,
		callback: (error: Error | null, isValid: boolean) => void,
	) {
		const allowedOrigins = [
			"http://localhost:2000",
			"http://localhost:3000",
			// "https://mobileacademy.io",
			// "https://wecancode.in",
		];

		/// check if the origin is in the allowedOrigins array
		if (!origin || allowedOrigins.includes(origin)) {
			callback(null, true);
		} else {
			callback(new Error("Not allowed by CORS"), false);
		}
	},
	methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
	credentials: true,
};

// middlerware to enable the helmet
app.use(helmet());
// middleware to enable the rate limit
app.use(globalRateLimit);
// middleware to enable the cors
app.use(cors(corsOptions));
// middleware to parse the cookies
app.use(cookieParser());
// middleware to parse the json
app.use(express.json({ limit: "10kb" }));
// middleware to sanitize the data
mongoSanitize.sanitize(payload);

// middleware to serve static files  from public folder
app.use(express.static("public"));
// set the view engine as ejs
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "view"));

// WEB ROUTES
app.use("/", homeRouter);
app.use("/verify-email", authRouter);
app.use("/password", authRouter);

// API ROUTES
app.use("/api/v1/auth", authRouter);
app.use("/api/v1/users", userRouter);
app.use("/api/v1/admin", adminRouter);
app.use("/api/v1/contacts", contactRouter);

/**
 * The app.all() middleware function in your code is a catch-all route handler
 * that gets executed for all incoming requests that do not match any of the defined routes.
 * This middleware function is used to handle 404 errors,
 * i.e., when a route is requested that does not exist on the server.
 */
app.all(/(.*)/, (req: Request, res: Response, next: NextFunction) => {
	next(
		new AppError(
			`Can't find ${req.originalUrl} on this server!`,
			HttpStatusCode.NOT_FOUND,
		),
	);
});

/**
 * The app.use(globalErrorHandler); is responsible for using the globalErrorHandler middleware function
 * for all incoming requests. This middleware function is used to handle errors
 * that occur during the request-response cycle.
 */
app.use(globalErrorHandler);

export default app;
