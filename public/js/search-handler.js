/**
 * Utility to sync search params to URL
 */
class SearchSyncManager {
	/**
	 * Update URL with search params without triggering page reload
	 * @param {Object} params - Search parameters (query, paperId, year, page, etc)
	 * @param {boolean} replace - Use replaceState instead of pushState (default: false)
	 */
	static syncToURL(params, replace = false) {
		const searchParams = new URLSearchParams(globalThis.location.search);

		// Only add non-empty params
		Object.entries(params).forEach(([key, value]) => {
			if (value === null || value === undefined || value === "") {
				searchParams.delete(key);
			} else if (Array.isArray(value)) {
				searchParams.delete(key);
				value.forEach((v) => searchParams.append(key, v));
			} else {
				searchParams.set(key, value);
			}
		});

		const queryString = searchParams.toString();
		const newURL = queryString
			? `${globalThis.location.pathname}?${queryString}`
			: globalThis.location.pathname;

		if (replace) {
			globalThis.history.replaceState({ ...params }, "", newURL);
		} else {
			globalThis.history.pushState({ ...params }, "", newURL);
		}
	}
}
