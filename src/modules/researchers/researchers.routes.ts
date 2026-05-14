import { Router, type Request, type Response } from "express";
import asyncHandler from "../../lib/async.handler.js";
import researchersService from "./researchers.service.js";
import { paginationMiddleware } from "../../middlewares/pagination.js";
import { type PaginatedRequest } from "../../types/paginatedRequest.js";
import isAdmin from "../../middlewares/authorize.js";
import { uploadExcel } from "../../middlewares/uploads.js";
import { validate } from "../../middlewares/validator.js";
import {
	FilterQuerySchema,
	UploadOptionsSchema,
	AnalyzeRequestSchema,
	type AnalyzeRequest,
	type UploadOptions,
} from "./researchers.schema.js";
import type { TypedRequest } from "../../types/Request.js";

const router = Router();

// 1. Fetch distinct Main Topics
router.get(
	"/local-researchers/main-topics",
	asyncHandler(async (_: Request, res: Response) => {
		const topics = await researchersService.getMainTopics();
		res.json(topics);
	}),
);

// 2. Filter Researchers
router.get(
	"/local-researchers/filter",
	paginationMiddleware,
	validate(FilterQuerySchema, "query"),
	asyncHandler(
		async (req: PaginatedRequest & { validatedQuery: any }, res: Response) => {
			const pagination = req.pagination;
			const filters = req.validatedQuery;
			const researchers = await researchersService.getResearchers(
				pagination,
				filters,
			);
			res.json(researchers);
		},
	),
);

router.get(
	"/local-researchers",
	asyncHandler(async (_: Request, res: Response) => {
		const numbers = await researchersService.getResearchersDashboard();
		res.json(numbers);
	}),
);

// 3. Upload Researchers (Admin Only)
router.post(
	"/admin/upload-researchers",
	isAdmin,
	uploadExcel.single("file"),
	validate(UploadOptionsSchema),
	asyncHandler(async (req: TypedRequest<UploadOptions>, res: Response) => {
		if (!req.file?.buffer) {
			return res
				.status(400)
				.json({ error: "No file uploaded or invalid format" });
		}

		const options = req.validatedData;
		const count = await researchersService.uploadResearchers(
			req.file.buffer,
			options,
		);

		res.json({
			success: true,
			message: `Database synced! Added ${count} researchers.`,
		});
	}),
);

// 4. Analyze Researcher
router.post(
	"/local-researchers/analyze",
	validate(AnalyzeRequestSchema),
	asyncHandler(async (req: TypedRequest<AnalyzeRequest>, res: Response) => {
		const result = await researchersService.analyzeResearcher(
			req.validatedData.id,
		);
		res.json(result);
	}),
);

export default router;
