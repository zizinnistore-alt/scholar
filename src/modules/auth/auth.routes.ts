import { Router, type Response } from "express";
import { validate } from "../../middlewares/validator.js";
import asyncHandler from "../../lib/async.handler.js";
import { loginSchema } from "./auth.schema.js";
import type { TypedRequest } from "../../types/Request.js";
import type { z } from "zod";
import { authService } from "./auth.service.js";

const router = Router();

router.post(
	"/login", // route
	validate(loginSchema), // validation
	// async handler to pass the error to the error handler
	asyncHandler(
		async (req: TypedRequest<z.infer<typeof loginSchema>>, res: Response) => {
			const { email, password } = req.validatedData;
			const response = await authService.login(email, password);

			res.cookie("auth_token", response.token, {
				httpOnly: true,
				secure: false,
				maxAge: 24 * 60 * 60 * 1000,
			});

			return res.json(response);
		},
	),
);

export default router;
