import { Router, type Response } from "express";
import isAuthenticated from "../../middlewares/auth.js";
import isAdmin from "../../middlewares/authorize.js";
import asyncHandler from "../../lib/async.handler.js";
import { validate } from "../../middlewares/validator.js";
import { feedbackSchema, type Feedback } from "./feedback.schema.js";
import feedbackService from "./feedback.service.js";
import type { TypedRequest } from "../../types/Request.js";
import { paginationMiddleware as pagination } from "../../middlewares/pagination.js";
import type { PaginatedRequest } from "../../types/paginatedRequest.js";

const router = Router();

router.get(
	"/",
	isAuthenticated,
	isAdmin,
	pagination,
	asyncHandler(async (req: PaginatedRequest, res: Response) => {
		const feedbacks = await feedbackService.getFeedbacks(req.pagination);
		res.status(200).json(feedbacks);
	}),
);

router.post(
	"/",
	validate(feedbackSchema),
	asyncHandler(async (req: TypedRequest<Feedback>, res: Response) => {
		const feedbackData = req.validatedData;
		await feedbackService.submitFeedback(feedbackData);
		res.status(201).json({ success: true, message: "Feedback received." });
	}),
);

export default router;
