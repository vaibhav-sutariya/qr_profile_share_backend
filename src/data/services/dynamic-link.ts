import { Request, Response, NextFunction } from "express";
import axios from "axios";
import catchAsync from "../../utils/catch-async.js";
import {
	IDynamicLinkRequest,
	IDynamicLinkResponse,
} from "../dtos/dynamicLinkTypes";
import dotenv from "dotenv";
dotenv.config();

export const generateDynamicLink = catchAsync(
	async (
		req: Request<
			Record<string, unknown>,
			Record<string, unknown>,
			IDynamicLinkRequest
		>,
		res: Response<IDynamicLinkResponse>,
		next: NextFunction,
	): Promise<void> => {
		const { id, name, email, photo, position, location } = req.body;

		const dynamicLinkPayload = {
			dynamicLinkInfo: {
				domainUriPrefix: process.env.DOMAIN_URI_PREFIX,
				link: `${process.env.DEEP_LINK_DOMAIN}/api/v1/users/getOneUser/${id}`,
				androidInfo: {
					androidPackageName: process.env.PACKAGE_NAME,
				},
				iosInfo: {
					iosBundleId: process.env.PACKAGE_NAME,
				},
				socialMetaTagInfo: {
					socialTitle: "QR Profile",
					socialDescription: `${name} - ${position}`,
					socialImageLink:
						photo || `${process.env.DEEP_LINK_DOMAIN}/default.png`,
				},
			},
			suffix: {
				option: "SHORT",
			},
		};

		const response = await axios.post(
			`https://firebasedynamiclinks.googleapis.com/v1/shortLinks?key=${process.env.API_KEY}`,
			dynamicLinkPayload,
		);

		res.status(200).json({
			status: "success",
			link: response.data.shortLink,
		});
	},
);
