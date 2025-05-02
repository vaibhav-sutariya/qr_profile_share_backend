import { Request, Response, NextFunction } from "express";
import catchAsync from "../../utils/catch-async.js";
import dotenv from "dotenv";
import { me } from "../controllers/user/user-controller.js";
dotenv.config();

export const generateDynamicLink = catchAsync(
	async (req: Request, res: Response, next: NextFunction): Promise<void> => {
		const { id, name, email, photo, position, location } = req.body;
		const longLink = `https://randomqr.page.link/?link=${encodeURIComponent(
			`https://qr-profile-share-backend.onrender.com/api/v1/users/getOneUser/${id}`,
		)}&apn=com.example.qr_profile_share&afl=${encodeURIComponent(
			"https://play.google.com/store/apps/details?id=com.example.qr_profile_share",
		)}`;

		res.status(200).json({
			status: "success",
			message: "Dynamic link generated successfully",
			link: longLink,
		});
	},
);
