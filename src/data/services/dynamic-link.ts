import { Request, Response, NextFunction } from "express";
import catchAsync from "../../utils/catch-async.js";
import dotenv from "dotenv";
import { me } from "../controllers/user/user-controller.js";
dotenv.config();

export const generateDynamicLink = catchAsync(
	async (req: Request, res: Response, next: NextFunction): Promise<void> => {
		const { id, name, email, photo, position, location } = req.body;
		const longLink = `${process.env.DOMAIN_URI_PREFIX}/?link=${encodeURIComponent(
			`${process.env.DEEP_LINK_DOMAIN}/api/v1/users/getOneUser/${id}`,
		)}&apn=${process.env.PACKAGE_NAME}&afl=${encodeURIComponent(
			"https://play.google.com/store/apps/details?id=com.quikhitch",
		)}`;

		res.status(200).json({
			status: "success",
			message: "Dynamic link generated successfully",
			link: longLink,
		});
	},
);
