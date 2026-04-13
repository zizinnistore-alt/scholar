import jwt from "jsonwebtoken";
import { authConfig } from "../config/index.js";
import type { NextFunction, Response } from "express";
import type { AuthRequest } from "../types/AuthRequest.js";

const isAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
	const token = req.cookies.auth_token; // tokens from cookies

	if (!token) {
		return res.status(401).json({ error: "Access Denied. No token provided." });
	}

	try {
		const decoded = jwt.verify(token, authConfig.jwtSecret) as jwt.JwtPayload;
		if (decoded.role !== "admin") {
			return res.status(403).json({ error: "Access Denied. Admins only." });
		}
		req.user = decoded; // save if needed
		next(); // pass
	} catch (ex) {
		console.error("Token verification failed:", ex);
		res.status(400).json({ error: "Invalid token." });
	}
};

export default isAdmin;
