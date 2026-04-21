import { Router, type Response } from "express";
import { validate } from "../../middlewares/validator.js";
import asyncHandler from "../../lib/async.handler.js";
import { loginSchema, registerSchema } from "./auth.schema.js";
import type { TypedRequest } from "../../types/Request.js";
import type { z } from "zod";
import { authService } from "./auth.service.js";

const attachCookie = (res: Response, token: string) => {
	res.cookie("auth_token", token, {
		httpOnly: true,
		secure: true,
		sameSite: "none",
		maxAge: 24 * 60 * 60 * 1000, // 24 hours
	});
};

const router = Router();

router.post(
	"/login", // route
	validate(loginSchema), // validation
	// async handler to pass the error to the error handler
	asyncHandler(
		async (req: TypedRequest<z.infer<typeof loginSchema>>, res: Response) => {
			const { email, password } = req.validatedData;
			const response = await authService.login(email, password);

			attachCookie(res, response.token);

			return res.json(response);
		},
	),
);

router.post(
	"/register",
	validate(registerSchema),
	asyncHandler(
		async (
			req: TypedRequest<z.infer<typeof registerSchema>>,
			res: Response,
		) => {
			const response = await authService.register(req.validatedData);
			attachCookie(res, response.token);
			return res.status(response.statusCode).json({
				success: response.success,
				message: response.message,
				user: response.user,
			});
		},
	),
);

router.post(
	"/logout",
	asyncHandler(async (req: Request, res: Response) => {
		res.clearCookie("auth_token", {
			httpOnly: true,
			secure: true,
			sameSite: "none",
		});
		return res.json({ success: true, message: "Logged out" });
	}),
);

export default router;
