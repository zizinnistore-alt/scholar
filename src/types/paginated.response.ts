class PaginatedResponse<T> {
	constructor(
		public data: T[],
		public total: number,
		public page: number,
		public hasPreviousPage: boolean,
		public hasNextPage: boolean,
	) {}
}

export default PaginatedResponse;
