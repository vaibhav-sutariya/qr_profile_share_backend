class AppError extends Error {
	public statusCode: number;
	public status: string;
	public isOperational: boolean;

	/**
	 * Creates a new instance of the AppError class.
	 *
	 * @param {string} message - The error message.
	 * @param {number} statusCode - The HTTP status code associated with the error.
	 */
	constructor(message: string, statusCode: number) {
		super(message);

		this.statusCode = statusCode;
		this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
		this.isOperational = true;

		Error.captureStackTrace(this, this.constructor);
	}
}

export default AppError;
