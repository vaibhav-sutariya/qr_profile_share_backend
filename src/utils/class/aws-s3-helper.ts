import {
	DeleteObjectCommand,
	GetObjectCommand,
	GetObjectCommandInput,
	PutObjectCommand,
	PutObjectCommandInput,
	S3Client,
} from "@aws-sdk/client-s3";
import AppError from "../app-error.js";
import HttpStatusCode from "../http-status-code.js";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

class AwsS3Helper {
	private static instance: AwsS3Helper;
	private readonly s3Client: S3Client;

	/**
	 * Constructs a new instance of the class by initializing the S3 client with the provided AWS credentials.
	 *
	 * @throws {AppError} If the AWS S3 credentials are not found in the environment variables.
	 */
	private constructor() {
		const region = process.env.S3_BUCKET_REGION;
		const accessKeyId = process.env.S3_BUCKET_KEY;
		const secretAccessKey = process.env.S3_BUCKET_SECRET_KEY;

		if (!region || !accessKeyId || !secretAccessKey) {
			throw new AppError(
				"AWS S3 credentials not found",
				HttpStatusCode.INTERNAL_SERVER_ERROR,
			);
		}

		this.s3Client = new S3Client({
			region,
			credentials: { accessKeyId, secretAccessKey },
		});
	}

	/**
	 * Returns an instance of the AwsS3Helper class. If an instance does not exist,
	 * creates a new instance and returns it.
	 *
	 * @return {AwsS3Helper} An instance of the AwsS3Helper class.
	 */
	public static getInstance(): AwsS3Helper {
		if (!AwsS3Helper.instance) {
			AwsS3Helper.instance = new AwsS3Helper();
		}
		return AwsS3Helper.instance;
	}

	/**
	 * Uploads an object to the specified S3 bucket.
	 *
	 * @param {string} key - The key under which the object will be stored in the bucket.
	 * @param {any} body - The content of the object to be uploaded.
	 * @param {string} contentType - The content type of the object.
	 * @return {Promise<void>} - A promise that resolves when the object is successfully uploaded.
	 * @throws {Error} - If there is an error during the upload process.
	 */
	public async uploadObject(
		key: string,
		body: Buffer,
		contentType: string,
	): Promise<void> {
		try {
			const params: PutObjectCommandInput = {
				Bucket: process.env.S3_BUCKET_NAME || "",
				Key: key,
				Body: body,
				ContentType: contentType,
			};
			const command = new PutObjectCommand(params);
			// send the object to s3
			await this.s3Client.send(command);
		} catch (error) {
			if (error instanceof Error) {
				throw new AppError(
					error.message,
					HttpStatusCode.INTERNAL_SERVER_ERROR,
				);
			}
		}
	}

	/**
	 * Deletes an object from the specified S3 bucket.
	 *
	 * @param {string} key - The key of the object to be deleted.
	 * @return {Promise<void>} A promise that resolves when the object is successfully deleted.
	 * @throws {Error} If there is an error during the deletion process.
	 */
	public async deleteObject(key: string): Promise<void> {
		try {
			const bucket = process.env.S3_BUCKET_NAME || "";
			await this.s3Client.send(
				new DeleteObjectCommand({ Bucket: bucket, Key: key }),
			);
		} catch (error) {
			if (error instanceof Error) {
				throw new AppError(
					error.message,
					HttpStatusCode.INTERNAL_SERVER_ERROR,
				);
			}
		}
	}

	/**
	 * Retrieves a signed URL for accessing an object in an S3 bucket.
	 *
	 * @param {string} key - The key of the object to be accessed.
	 * @param {number} expiresIn - The duration (in seconds) for which the signed URL will be valid.
	 * @return {Promise<string>} A promise that resolves with the signed URL for accessing the object.
	 * @throws {Error} If there is an error generating the signed URL.
	 */
	public async getSignedUrl(
		key: string,
		expiresIn: number,
	): Promise<string | undefined> {
		try {
			const params: GetObjectCommandInput = {
				Bucket: process.env.S3_BUCKET_NAME || "",
				Key: key,
			};

			const command = new GetObjectCommand(params);
			// generate signed url - that will expires in [expiresIn]
			const url = await getSignedUrl(this.s3Client, command, {
				expiresIn: expiresIn,
			});
			return url;
		} catch (error) {
			if (error instanceof Error) {
				throw new AppError(
					error.message,
					HttpStatusCode.INTERNAL_SERVER_ERROR,
				);
			}
		}
	}
}

export default AwsS3Helper;
