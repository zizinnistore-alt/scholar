import type { TypedRequest } from "../types/Request.js";
import type { NextFunction, Response } from "express";
import type { z } from "zod";

export const validate =
	<T>(schema: z.ZodType<T>, key: "body" | "query" | "params" = "body") =>
	(req: TypedRequest<T>, res: Response, next: NextFunction) => {
		const result = schema.safeParse(req[key]);

		if (!result.success) {
			return next(result.error);
		}

		req.validatedData = result.data;
		next();
	};
