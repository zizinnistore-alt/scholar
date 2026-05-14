import { type PaginationMeta } from "../utils/pagination.util.js";
import { type Request } from "express";

export interface PaginatedRequest extends Request {
	pagination: PaginationMeta;
}

