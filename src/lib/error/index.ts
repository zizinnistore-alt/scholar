import { BaseError } from "./BaseError.js";

export class UnauthorizedError extends BaseError {
	statusCode = 401;
	constructor(public message: string = "Unauthorized") {
		super(message);
	}
}

export class ForbiddenError extends BaseError {
	statusCode = 403;
	constructor(public message: string = "Forbidden") {
		super(message);
	}
}

export class NotFoundError extends BaseError {
	statusCode = 404;
	constructor(public message: string = "Resource not found") {
		super(message);
	}
}

export class ConflictError extends BaseError {
	statusCode = 409;
	constructor(public message: string = "Resource already exists") {
		super(message);
	}
}

export class ValidationError extends BaseError {
	statusCode = 422;
	constructor(public message: string = "Validation failed") {
		super(message);
	}
}
