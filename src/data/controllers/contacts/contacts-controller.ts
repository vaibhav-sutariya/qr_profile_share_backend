import { NextFunction, Response } from "express";
import { Request } from "express-serve-static-core";
import catchAsync from "../../../utils/catch-async.js";
import AppError from "../../../utils/app-error.js";
import HttpStatusCode from "../../../utils/http-status-code.js";
import multer, { FileFilterCallback } from "multer";
import sharp from "sharp";
import Contact from "../../../model/contact-model.js";
import crypto from "crypto";
import User from "../../../model/user-model.js";

/**
 * @param {Request} req
 * @param {Express.Multer.File} file
 * @param {FileFilterCallback} callback
 * @return {void}
 */

export const scanAndCreateContact = catchAsync(
	async (req: Request, res: Response, next: NextFunction) => {
		const scannedUserId = req.body.userId; // From QR Code
		const scannerUserId = req.user.id;
		const tags = req.body.tags;

		if (scannedUserId === scannerUserId) {
			return next(
				new AppError(
					"You cannot save your own profile as a contact.",
					400,
				),
			);
		}

		const scannedUser = await User.findById(scannedUserId).select(
			"name email phoneNumber company website userRole location socialLinks photo userRole",
		);

		if (!scannedUser) {
			return next(
				new AppError("User not found.", HttpStatusCode.NOT_FOUND),
			);
		}

		// Check if already exists
		const alreadyExists = await Contact.findOne({
			userId: scannerUserId,
			email: scannedUser.email,
		});

		if (alreadyExists) {
			return next(
				new AppError("This user is already added as a contact.", 400),
			);
		}

		const contactId = crypto.randomBytes(16).toString("hex");

		const newContact = await Contact.create({
			contactId,
			userId: scannerUserId, // who scanned
			name: scannedUser.name,
			email: scannedUser.email,
			phoneNumber: scannedUser.phoneNumber,
			company: scannedUser.company,
			userRole: scannedUser.userRole,
			website: scannedUser.website,
			location: scannedUser.location,
			socialLinks: scannedUser.socialLinks,
			photo: scannedUser.photo,
			role: scannedUser.role,
			tags: tags,
		});

		res.status(HttpStatusCode.CREATED).json({
			status: "success",
			message: "Contact added successfully.",
			data: newContact,
		});
	},
);

export const getAllContacts = catchAsync(
	async (req: Request, res: Response, next: NextFunction) => {
		const userId = req.user.id; // user ID from authentication middleware

		const page = parseInt(req.query.page as string) || 1;
		const limit = parseInt(req.query.limit as string) || 10;
		const skip = (page - 1) * limit;

		const contacts = await Contact.find({ userId })
			.skip(skip)
			.limit(limit)
			.sort({ createdAt: -1 });

		const totalContacts = await Contact.countDocuments({ userId });

		res.status(HttpStatusCode.OK).json({
			status: "success",
			results: contacts.length,
			total: totalContacts,
			page,
			totalPages: Math.ceil(totalContacts / limit),
			data: contacts,
		});
	},
);

export const getContactById = catchAsync(
	async (req: Request, res: Response, next: NextFunction) => {
		const contactId = req.params.id; // from URL

		const contact = await Contact.findById(contactId);
		if (!contact) {
			return next(
				new AppError(
					"Contact not found or does not belong to you.",
					HttpStatusCode.NOT_FOUND,
				),
			);
		}

		res.status(HttpStatusCode.OK).json({
			status: "success",
			data: contact,
		});
	},
);

export const deleteContactById = catchAsync(
	async (req: Request, res: Response, next: NextFunction) => {
		const contactId = req.params.id; // from URL

		const deletedContact = await Contact.findByIdAndDelete(contactId);

		if (!deletedContact) {
			return next(
				new AppError(
					"No contact found with this ID or it does not belong to you.",
					HttpStatusCode.NOT_FOUND,
				),
			);
		}

		res.status(HttpStatusCode.OK).json({
			status: "success",
			message: "Contact deleted successfully.",
		});
	},
);

export const addNewContact = catchAsync(
	async (req: Request, res: Response, next: NextFunction) => {
		const userId = req.user.id; // user ID from authentication middleware
		// Check if a contact with the same email already exists for this user
		const existingContact = await Contact.findOne({
			userId,
			email: req.body.email,
		});
		if (existingContact) {
			return next(
				new AppError(
					"This contact is already added.",
					HttpStatusCode.BAD_REQUEST,
				),
			);
		}
		const newContact = await Contact.create({
			userId,
			contactId: crypto.randomBytes(16).toString("hex"),
			photo: req.body.photo,
			name: req.body.name,
			email: req.body.email,
			phoneNumber: req.body.phoneNumber,
			location: req.body.location,
			company: req.body.company,
			userRole: req.body.userRole,
			website: req.body.website,
		});

		if (!newContact) {
			return next(
				new AppError(
					"Failed to add new contact.",
					HttpStatusCode.BAD_REQUEST,
				),
			);
		}

		res.status(HttpStatusCode.CREATED).json({
			status: "success",
			message: "Contact added successfully.",
			data: newContact,
		});
	},
);
