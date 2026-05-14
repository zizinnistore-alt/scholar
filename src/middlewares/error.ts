import type { Request, Response, NextFunction } from "express";
import { BaseError } from "../lib/error/BaseError.js";

// each entry handles one third-party error type
// adding a new one = adding one object here, nothing else changes
const externalErrorHandlers: {
	match: (err: Error) => boolean;
	statusCode: number;
	message: (err: Error) => string;
}[] = [
	{
		match: (err) => err.name === "MulterError",
		statusCode: 400,
		message: (err) => err.message,
	},
	{
		match: (err) => err.name === "ZodError",
		statusCode: 422,
		message: () => "Invalid request data",
	},
];

export const errorHandler = (
	err: Error,
	_: Request,
	res: Response,
	__: NextFunction,
) => {
	// our own errors — they know how to represent themselves
	if (err instanceof BaseError) {
		return res.status(err.statusCode).json(err.toResponse());
	}

	// third-party errors — matched by registry, no if/else chain
	const external = externalErrorHandlers.find((h) => h.match(err));
	if (external) {
		return res.status(external.statusCode).json({
			status: "error",
			message: external.message(err),
		});
	}

	// truly unknown — don't leak internals
	console.error("Unhandled error:", err);
	return res.status(500).json({
		status: "error",
		message: "Something went wrong",
	});
};
