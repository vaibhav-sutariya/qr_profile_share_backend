import { IUser } from "../model/user-model";
// import { Request } from "express-serve-static-core";
// import { Express } from "express-serve-static-core";

/**
 * declare global: This line is saying that you want to extend a global, built-in object.
 * This is necessary if you want to add properties or methods to objects/types that are accessible throughout your project,
 * such as e.g., console, Window, or in this case, Express.
 *
 * namespace Express: Here, you are specifying that you want to add something to the Express 'namespace'
 * (an abstract container holding different types, interfaces, classes etc related to Express).
 *
 * interface Request: Here, you're saying you want to augment (add more properties to)
 * the Request interface in the Express namespace.
 *
 * user?: {...}: Inside this interface,
 * you are describing a new property user that Express Request objects may optionally have (? denotes that the property is optional).
 * This user object has properties id, email, and name, all of type string.
 */
declare global {
	namespace Express {
		interface Request {
			user: IUser;
		}
	}
}
