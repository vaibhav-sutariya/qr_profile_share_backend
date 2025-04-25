import { RequestHandler, Router } from "express";
import {
	createNewToken,
	firebasePhoneLogin,
	firebaseSolicalLogin,
	forgotPasword,
	login,
	passwordResetFailure,
	passwordResetSuccess,
	protect,
	resetPassword,
	resetPasswordView,
	resetPasswordWeb,
	signup,
	updatePassword,
	verifyEmail,
} from "../data/controllers/auth/auth-controller.js";

const router = Router();

// WEB - server side rendering
router.post("/reset", resetPasswordWeb as RequestHandler);
router.get("/reset/:token", resetPasswordView as RequestHandler);
router.get("/reset/status/success", passwordResetSuccess as RequestHandler);
router.get("/reset/status/failure", passwordResetFailure as RequestHandler);

// API
router.post("/signup", signup as RequestHandler);
router.post("/login", login as RequestHandler);
router.get("/:token", verifyEmail as RequestHandler);
router.post("/refresh-token", createNewToken as RequestHandler);
router.post("/forgot-password", forgotPasword as RequestHandler);
router.patch("/reset-password/:token", resetPassword as RequestHandler);
router.patch("/update-my-password", protect, updatePassword as RequestHandler);
router.post("/firebase-solical-login", firebaseSolicalLogin as RequestHandler);
router.post("/firebase-phone-login", firebasePhoneLogin as RequestHandler);

export default router;
