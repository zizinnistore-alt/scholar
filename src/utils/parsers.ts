/**
 * Parses a CSV row string handling quoted fields with embedded commas
 * Iterates through each character, tracking quote state to determine field boundaries.
 * Trims whitespace from each field value.
 *
 * @param {string} str - The CSV row string to parse (e.g., "John,Doe,\"Smith, Jr.\"")
 * @returns {string[]} Array of parsed field values with trimmed whitespace
 *
 * @example
 * parseCSVRow("name,age,\"city, country\"")
 * // Returns: ["name", "age", "city, country"]
 */
const parseCSVRow = (str: string): string[] => {
	const result = [];
	let curr = "";
	let inQuotes = false;
	for (const element of str) {
		let c = element; // SOLVED
		if (c === '"') inQuotes = !inQuotes;
		else if (c === "," && !inQuotes) {
			result.push(curr.trim());
			curr = "";
		} else curr += c;
	}
	result.push(curr.trim());
	return result;
};

export { parseCSVRow };
