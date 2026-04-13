export abstract class BaseError extends Error {
	abstract statusCode: number;
	abstract message: string;

	constructor(message: string) {
		super(message);
		this.name = this.constructor.name;
	}

	toResponse() {
		return {
			status: "error",
			message: this.message,
		};
	}
}
