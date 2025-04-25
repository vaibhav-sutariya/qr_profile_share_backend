//import { NextFunction } from "express-serve-static-core";

import HttpStatusCode from "../utils/http-status-code.js";
import AppError from "./app-error.js";
import { NextFunction, Request, Response } from "express";
import mongoose from "mongoose";

interface ExtendedMonogoError extends mongoose.mongo.MongoError {
	keyValue?: Record<string, unknown>;
}

const isMongoDBError = (err: Error): err is ExtendedMonogoError => {
	return err instanceof mongoose.mongo.MongoError;
};

const sendErrorDev = (err: AppError, req: Request, res: Response) => {
	err.statusCode = err.statusCode || HttpStatusCode.INTERNAL_SERVER_ERROR;
	err.status = err.status || "error";

	res.status(err.statusCode).json({
		status: err.status,
		message: err.message,
		erroe: err,
		stackTrack: err.stack,
	});
};

const sendErrorProd = (err: AppError, req: Request, res: Response) => {
	if (isMongoDBError(err)) {
		const error = { ...err };
		if (error.code === 11000) {
			const keyValue = error.keyValue;
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
			const [key, value] = Object.entries(
				keyValue as Record<string, unknown>,
			)[0];

			return res.status(HttpStatusCode.CONFLICT).json({
				status: "fail",
				message: `Duplicate field key ${key} and value: ${value as string}. Please use another value!`,
			});
		}
	}
	if (err.isOperational) {
		err.statusCode = err.statusCode || HttpStatusCode.INTERNAL_SERVER_ERROR;
		err.status = err.status || "error";
		res.status(err.statusCode).json({
			status: err.status,
			message: err.message,
		});
	} else {
		res.status(err.statusCode === undefined ? 500 : err.statusCode).json({
			status: "error",
			message: err.message || "Something went very wrong!",
		});
	}
};

/**
 * Global error handler for handling different error scenarios based on the environment.
 *
 * @param {AppError} err - The error object to be handled
 * @param {Request} req - The request object
 * @param {Response} res - The response object
 * @param {NextFunction} next - The next function in the middleware chain
 */

const globalErrorHandler = (
	err: AppError,
	req: Request,
	res: Response,
	// eslint-disable-next-line @typescript-eslint/no-unused-vars
	next: NextFunction,
) => {
	if (process.env.NODE_ENV === "development") {
		sendErrorDev(err, req, res);
	} else if (process.env.NODE_ENV === "production") {
		sendErrorProd(err, req, res);
	} else {
		res.status(err.statusCode).json({
			status: err.status,
			message: err.message,
		});
	}
};

export default globalErrorHandler;
