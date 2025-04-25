import { RequestHandler, Router } from "express";
import { protect } from "../data/controllers/auth/auth-controller.js";
const router = Router();
import {
	scanAndCreateContact,
	getAllContacts,
	getContactById,
	deleteContactById,
	addNewContact,
	// getAllContacts,
	// getContactById,
} from "../data/controllers/contacts/contacts-controller.js";
router.use(protect);
router.post("/create-contact", scanAndCreateContact as RequestHandler);
router.get("/contacts", protect, getAllContacts);
router.get("/getOneContact/:id", protect, getContactById);
router.delete("/deleteContacts/:id", protect, deleteContactById);
router.post("/addNewContact", protect, addNewContact);

export default router;
