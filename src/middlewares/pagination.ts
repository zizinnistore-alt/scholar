import type { NextFunction, Response } from "express";
import { z, ZodError } from "zod";
import type { PaginatedRequest } from "../types/paginatedRequest.js";

const PaginationSchema = z.object({
	page: z
		.string()
		.optional()
		.default("1")
		.transform(Number)
		.pipe(z.number().int().min(1, "page must be >= 1")),

	limit: z
		.string()
		.optional()
		.default("20")
		.transform(Number)
		.pipe(z.number().int().min(1).max(100, "limit must be <= 100")),

	sortBy: z.string().optional().default("createdAt"),

	sortOrder: z.enum(["asc", "desc"]).optional().default("desc"),
});

export const paginationMiddleware = (
	req: PaginatedRequest,
	res: Response,
	next: NextFunction,
): void => {
	try {
		const parsed = PaginationSchema.parse(req.query);

		req.pagination = {
			page: parsed.page,
			limit: parsed.limit,
			offset: (parsed.page - 1) * parsed.limit,
			sortBy: parsed.sortBy,
			sortOrder: parsed.sortOrder,
		};

		next();
	} catch (error) {
		if (error instanceof ZodError) {
			res.status(400).json({
				success: false,
				message: "Invalid pagination parameters",
				errors: z.treeifyError(error).errors.join("\n"),
			});
			return;
		}
		next(error);
	}
};

export type PaginationQuery = z.infer<typeof PaginationSchema>;
export default paginationMiddleware;
