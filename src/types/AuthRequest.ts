import jwt from "jsonwebtoken";
import type { Request } from "express";

export interface AuthRequest extends Request {
	user: string | jwt.JwtPayload;
}
