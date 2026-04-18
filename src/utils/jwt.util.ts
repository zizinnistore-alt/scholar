import jwt from "jsonwebtoken";
import { authConfig } from "../config/index.js";
const JWT_SECRET = authConfig.jwtSecret;

const generateToken = (user: any): string => {
	const token = jwt.sign(
		{ id: user.id, role: user.role, name: user.name },
		JWT_SECRET,
		{ expiresIn: "24h" },
	);
	return token;
};

const verifyToken = (token: string) => {
	const decoded = jwt.verify(token, JWT_SECRET);
	return decoded;
};

export { generateToken, verifyToken };
