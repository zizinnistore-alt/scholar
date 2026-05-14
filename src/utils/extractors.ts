//  HELPERS & STARTUP
// ================================================================

/**
 * Removes academic titles and suffixes from names to fix S2 API calls
 * Strips common academic prefixes (Professor, Dr., PhD, etc.) and removes text after commas.
 *
 * @param {string} name - Full name with academic titles/prefixes
 * @returns {string} Cleaned name without academic titles, with normalized whitespace
 *
 * @example
 * cleanName("Professor Dr. John Smith, PhD")
 * // Returns: "John Smith"
 */
const cleanName = (name: string): string => {
	return name
		.replace(
			/^(Professor\.|Professor|Prof\.|Dr\.|PhD Candidate at|PhD Candidate|Associate Professor|Assistant Professor|Ph\.D\.|MSc)\s+/gi,
			"",
		)
		.replace(/,.*/, "") // Remove anything after a comma
		.trim();
};

/**
 * Extracts data from a row object based on type and flexible keyword matching
 * Maps a data type to multiple possible column name keywords and finds a matching key
 * in the row object. Performs case-insensitive, alphanumeric-normalized matching.
 *
 * @param {Record<string, any>} row - Data row object to extract from (e.g., from CSV/Excel)
 * @param {string} type - Data type to extract: "name", "website", "linkedin", "glassdoor", "size", "category", "industry", "presence", or "location"
 * @returns {string} Extracted value or empty string if no matching key found
 *
 * @example
 * extractData({ "CompanyName": "Acme Corp", "Website": "acme.com" }, "name")
 * // Returns: "Acme Corp"
 *
 * extractData({ "CompanyName": "Acme Corp" }, "website")
 * // Returns: ""
 */
const extractData = (row: Record<string, any>, type: string): string => {
	const keywords = {
		name: ["companyname", "company", "name", "entity"],
		website: [
			"website",
			"web",
			"url",
			"companylink",
			"link",
			"site",
			"homepage",
		],
		linkedin: ["linkedin", "profile"],
		glassdoor: ["glassdoor", "review"],
		size: ["size", "employee", "staff", "number"],
		category: ["category", "cat", "sector"],
		industry: ["industry", "focus", "vlsi", "specialization"],
		presence: ["presence", "type", "status"],
		location: ["country", "state", "location", "region", "hq"],
	};

	const targetKeys = keywords[type] || [];
	const rowKeys = Object.keys(row);

	// Find matching key
	let matchKey = rowKeys.find((key) =>
		targetKeys.some((k: string) =>
			key
				.toLowerCase()
				.replace(/[^a-z]/g, "")
				.includes(k),
		),
	);

	let value = matchKey ? row[matchKey] : null;

	if (value && typeof value === "string") {
		return value.trim();
	}
	return "";
};

/**
 * Extracts the most common field of study from an array of paper objects
 * Counts frequency of all fields across papers and returns the most frequent one.
 * Falls back to defaults if no papers or fields are found.
 *
 * @param {Array<{fieldsOfStudy?: string[]}>} papers - Array of paper objects with fieldsOfStudy property
 * @returns {string} Most common field of study, or "Multidisciplinary" if frequency is tied, or "General Science" if no papers
 *
 * @example
 * extractTopField([
 *   { fieldsOfStudy: ["AI", "ML"] },
 *   { fieldsOfStudy: ["AI", "NLP"] }
 * ])
 * // Returns: "AI"
 */
const extractTopField = (papers: any[]): string => {
	if (!papers || papers.length === 0) return "General Science";
	const fieldCounts = {};
	papers.forEach((p) => {
		if (p.fieldsOfStudy) {
			p.fieldsOfStudy.forEach((field) => {
				fieldCounts[field] = (fieldCounts[field] || 0) + 1;
			});
		}
	});
	const sortedFields = Object.entries(fieldCounts).sort(
		(a, b) => +b[1] - +a[1],
	);
	return sortedFields.length > 0 ? sortedFields[0][0] : "Multidisciplinary";
};

/**
 * Finds a value from a row object using fuzzy keyword matching on object keys
 * Performs case-insensitive, alphanumeric-normalized key matching against keywords.
 * Returns the value of the first matching key, or empty string if no match.
 *
 * @param {Record<string, any>} row - Data row object to search
 * @param {string[]} keywords - Array of keywords to search for in row keys
 * @returns {string} Matched value (converted to string) or empty string if no match found
 *
 * @example
 * getFuzzyValue({ "LinkedInURL": "linkedin.com/...", "Email": "user@test.com" }, ["linkedin", "url"])
 * // Returns: "linkedin.com/..."
 */
const getFuzzyValue = (
	row: Record<string, any>,
	keywords: string[],
): string => {
	const keys = Object.keys(row);
	// Find a key that contains one of the keywords (case insensitive)
	const match = keys.find((key) =>
		keywords.some((word) =>
			key
				.toLowerCase()
				.replace(/[^a-z]/g, "")
				.includes(word),
		),
	);
	return match ? row[match] : "";
};

/**
 * Extracts a researcher's scholar ID from a profile link.
 * Supports Semantic Scholar (author IDs) and Google Scholar (user IDs).
 *
 * @param {string} link - The URL to extract the ID from
 * @returns {string} The extracted ID or an empty string if not found
 */
const extractScholarId = (link: string): string => {
	if (typeof link !== "string") return "";

	// 1. Semantic Scholar (just numbers)
	if (link.includes("semanticscholar.org")) {
		const match = link.match(/author\/(?:[^\/]+\/)?(\d+)/);
		return match ? match[1] : "";
	}

	// 2. Google Scholar (letters and numbers)
	if (link.includes("user=")) {
		const parts = link.split("user=");
		if (parts.length > 1) {
			return parts[1].split("&")[0];
		}
	}

	return "";
};

export {
	cleanName,
	extractData,
	extractTopField,
	getFuzzyValue,
	extractScholarId,
};

