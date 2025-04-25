import { RequestHandler, Router } from "express";
import {
	deleteMe,
	disableMe,
	getUserById,
	me,
	resizeProfileImage,
	updateMe,
	updateProfilePhtoto,
	uploadImage,
} from "../data/controllers/user/user-controller.js";
import { protect } from "../data/controllers/auth/auth-controller.js";

const router = Router();
// this will protect all the routes below with this middleware
// router.use(protect);

router.get("/me", protect, me as RequestHandler);
router.patch(
	"/update-profile-photo",
	protect,
	uploadImage,
	resizeProfileImage as RequestHandler,
	updateProfilePhtoto as RequestHandler,
);
router.patch("/update-me", protect, updateMe as RequestHandler);
router.delete("/delete-me", protect, deleteMe as RequestHandler);
router.patch("/disable-me", protect, disableMe as RequestHandler);
router.get("/getOneUser/:id", getUserById as RequestHandler);

export default router;
