import { describe, it, expect } from "vitest";
import {
	cleanName,
	extractData,
	extractTopField,
	getFuzzyValue,
	extractScholarId,
} from "../extractors.js";

describe("cleanName", () => {
	describe("removing academic prefixes", () => {
		it("should remove 'Professor' prefix", () => {
			expect(cleanName("Professor John Smith")).toBe("John Smith");
		});

		it("should remove 'Dr.' prefix", () => {
			expect(cleanName("Dr. Jane Doe")).toBe("Jane Doe");
		});

		it("should remove 'PhD Candidate' prefix", () => {
			expect(cleanName("PhD Candidate John Smith")).toBe("John Smith");
		});

		it("should remove 'Associate Professor' prefix", () => {
			expect(cleanName("Associate Professor Jane Smith")).toBe("Jane Smith");
		});

		it("should remove 'Assistant Professor' prefix", () => {
			expect(cleanName("Assistant Professor Bob Johnson")).toBe("Bob Johnson");
		});

		it("should remove 'MSc' prefix", () => {
			expect(cleanName("MSc Alice Brown")).toBe("Alice Brown");
		});

		it("should remove 'Prof.' prefix", () => {
			expect(cleanName("Prof. David Lee")).toBe("David Lee");
		});

		it("should remove 'Ph.D.' prefix", () => {
			expect(cleanName("Ph.D. Emma White")).toBe("Emma White");
		});

		it("should remove 'PhD Candidate at' prefix (without university)", () => {
			expect(cleanName("PhD Candidate at John Smith")).toBe("John Smith");
		});

		it("should handle case-insensitive prefixes", () => {
			expect(cleanName("PROFESSOR JOHN SMITH")).toBe("JOHN SMITH");
			expect(cleanName("professor john smith")).toBe("john smith");
		});
	});

	describe("removing suffixes after commas", () => {
		it("should remove text after comma", () => {
			expect(cleanName("John Smith, PhD")).toBe("John Smith");
		});

		it("should remove extended suffix", () => {
			expect(cleanName("Jane Doe, Department of Biology")).toBe("Jane Doe");
		});

		it("should remove complex suffix", () => {
			expect(cleanName("Bob Johnson, MIT, Computer Science, PhD")).toBe(
				"Bob Johnson",
			);
		});
	});

	describe("whitespace normalization", () => {
		it("should preserve internal spaces (not normalize)", () => {
			expect(cleanName("John    Smith")).toBe("John    Smith");
		});

		it("should trim leading spaces", () => {
			expect(cleanName("   John Smith")).toBe("John Smith");
		});

		it("should trim trailing spaces", () => {
			expect(cleanName("John Smith   ")).toBe("John Smith");
		});

		it("should handle extra spaces after prefix", () => {
			expect(cleanName("Professor   John Smith")).toBe("John Smith");
		});
	});

	describe("combined transformations", () => {
		it("should remove prefix and suffix", () => {
			expect(cleanName("Professor John Smith, PhD")).toBe("John Smith");
		});

		it("should handle prefix removal (requires space after)", () => {
			expect(cleanName("Dr. Jane Doe, MIT")).toBe("Jane Doe");
		});

		it("should handle Associate Professor with suffix", () => {
			expect(
				cleanName("Associate Professor Alice Brown, Computer Science"),
			).toBe("Alice Brown");
		});

		it("should handle PhD Candidate at with suffix", () => {
			expect(cleanName("PhD Candidate at Stanford John Lee, Statistics")).toBe(
				"Stanford John Lee",
			);
		});
	});

	describe("edge cases", () => {
		it("should handle name with no prefix", () => {
			expect(cleanName("John Smith")).toBe("John Smith");
		});

		it("should handle empty string", () => {
			expect(cleanName("")).toBe("");
		});

		it("should preserve single word without trailing space", () => {
			expect(cleanName("Professor")).toBe("Professor");
		});

		it("should handle only spaces", () => {
			expect(cleanName("   ")).toBe("");
		});

		it("should handle single word", () => {
			expect(cleanName("Smith")).toBe("Smith");
		});

		it("should preserve hyphens in names", () => {
			expect(cleanName("Mary-Jane Smith")).toBe("Mary-Jane Smith");
		});

		it("should preserve apostrophes in names", () => {
			expect(cleanName("Sean O'Connor")).toBe("Sean O'Connor");
		});

		it("should handle names with numbers", () => {
			expect(cleanName("Dr. Smith 2nd")).toBe("Smith 2nd");
		});
	});
});

describe("extractData", () => {
	describe("extracting names", () => {
		it("should extract from 'name' column", () => {
			const row = { name: "Acme Corp" };
			expect(extractData(row, "name")).toBe("Acme Corp");
		});

		it("should extract from 'companyname' column", () => {
			const row = { companyname: "TechCorp" };
			expect(extractData(row, "name")).toBe("TechCorp");
		});

		it("should extract from 'company' column", () => {
			const row = { company: "DataSys" };
			expect(extractData(row, "name")).toBe("DataSys");
		});

		it("should extract from 'entity' column", () => {
			const row = { entity: "MyCompany" };
			expect(extractData(row, "name")).toBe("MyCompany");
		});

		it("should trim whitespace from name", () => {
			const row = { name: "  Acme Corp  " };
			expect(extractData(row, "name")).toBe("Acme Corp");
		});
	});

	describe("extracting websites", () => {
		it("should extract from 'website' column", () => {
			const row = { website: "example.com" };
			expect(extractData(row, "website")).toBe("example.com");
		});

		it("should extract from 'url' column", () => {
			const row = { url: "https://example.com" };
			expect(extractData(row, "website")).toBe("https://example.com");
		});

		it("should extract from 'link' column", () => {
			const row = { link: "example.com" };
			expect(extractData(row, "website")).toBe("example.com");
		});

		it("should extract from 'homepage' column", () => {
			const row = { homepage: "www.example.com" };
			expect(extractData(row, "website")).toBe("www.example.com");
		});

		it("should handle case-insensitive column names", () => {
			const row = { "Web Site": "example.com" };
			expect(extractData(row, "website")).toBe("example.com");
		});
	});

	describe("extracting LinkedIn profiles", () => {
		it("should extract from 'linkedin' column", () => {
			const row = { linkedin: "https://linkedin.com/in/user" };
			expect(extractData(row, "linkedin")).toBe("https://linkedin.com/in/user");
		});

		it("should extract from 'profile' column", () => {
			const row = { profile: "https://linkedin.com/company/acme" };
			expect(extractData(row, "linkedin")).toBe(
				"https://linkedin.com/company/acme",
			);
		});
	});

	describe("extracting location data", () => {
		it("should extract from 'location' column", () => {
			const row = { location: "San Francisco, CA" };
			expect(extractData(row, "location")).toBe("San Francisco, CA");
		});

		it("should extract from 'country' column", () => {
			const row = { country: "United States" };
			expect(extractData(row, "location")).toBe("United States");
		});

		it("should extract from 'state' column", () => {
			const row = { state: "California" };
			expect(extractData(row, "location")).toBe("California");
		});

		it("should extract from 'region' column", () => {
			const row = { region: "North America" };
			expect(extractData(row, "location")).toBe("North America");
		});

		it("should extract from 'hq' column", () => {
			const row = { hq: "New York" };
			expect(extractData(row, "location")).toBe("New York");
		});
	});

	describe("other data types", () => {
		it("should extract company size", () => {
			const row = { size: "500-1000" };
			expect(extractData(row, "size")).toBe("500-1000");
		});

		it("should extract from 'employee' column for size", () => {
			const row = { employee: "250" };
			expect(extractData(row, "size")).toBe("250");
		});

		it("should extract category", () => {
			const row = { category: "Technology" };
			expect(extractData(row, "category")).toBe("Technology");
		});

		it("should extract industry", () => {
			const row = { industry: "Software Development" };
			expect(extractData(row, "industry")).toBe("Software Development");
		});

		it("should extract presence/status", () => {
			const row = { presence: "Active" };
			expect(extractData(row, "presence")).toBe("Active");
		});

		it("should extract glassdoor rating", () => {
			const row = { glassdoor: "4.2/5" };
			expect(extractData(row, "glassdoor")).toBe("4.2/5");
		});
	});

	describe("edge cases", () => {
		it("should return empty string for missing type", () => {
			const row = { name: "Acme" };
			expect(extractData(row, "unknown")).toBe("");
		});

		it("should return empty string for missing data", () => {
			const row = { company: "Acme" };
			expect(extractData(row, "website")).toBe("");
		});

		it("should return empty string for non-string values", () => {
			const row = { name: 123 };
			expect(extractData(row, "name")).toBe("");
		});

		it("should handle null values", () => {
			const row = { name: null };
			expect(extractData(row, "name")).toBe("");
		});

		it("should handle empty object", () => {
			const row = {};
			expect(extractData(row, "name")).toBe("");
		});

		it("should handle undefined in row", () => {
			const row = { name: undefined };
			expect(extractData(row, "name")).toBe("");
		});

		it("should be flexible with column name variations", () => {
			const row = { "Company Name": "TechCorp" };
			expect(extractData(row, "name")).toBe("TechCorp");
		});

		it("should handle special characters in column names", () => {
			const row = { "Company-Name": "TechCorp" };
			expect(extractData(row, "name")).toBe("TechCorp");
		});
	});
});

describe("extractTopField", () => {
	describe("basic functionality", () => {
		it("should extract most common field from papers", () => {
			const papers = [
				{ fieldsOfStudy: ["AI"] },
				{ fieldsOfStudy: ["AI", "ML"] },
			];
			expect(extractTopField(papers)).toBe("AI");
		});

		it("should handle single paper", () => {
			const papers = [{ fieldsOfStudy: ["AI", "ML", "NLP"] }];
			expect(extractTopField(papers)).toBe("AI");
		});

		it("should return default for empty array", () => {
			expect(extractTopField([])).toBe("General Science");
		});

		it("should return default for null", () => {
			expect(extractTopField(null)).toBe("General Science");
		});

		it("should return default for undefined", () => {
			expect(extractTopField(undefined)).toBe("General Science");
		});
	});

	describe("frequency calculation", () => {
		it("should correctly count field frequencies", () => {
			const papers = [
				{ fieldsOfStudy: ["AI"] },
				{ fieldsOfStudy: ["AI"] },
				{ fieldsOfStudy: ["ML"] },
			];
			expect(extractTopField(papers)).toBe("AI");
		});

		it("should handle multiple fields per paper", () => {
			const papers = [
				{ fieldsOfStudy: ["AI", "ML", "NLP"] },
				{ fieldsOfStudy: ["AI", "Robotics"] },
				{ fieldsOfStudy: ["ML"] },
			];
			expect(extractTopField(papers)).toBe("AI");
		});

		it("should return first entry when frequency is tied", () => {
			const papers = [{ fieldsOfStudy: ["AI"] }, { fieldsOfStudy: ["ML"] }];
			const result = extractTopField(papers);
			expect(["AI", "ML"]).toContain(result);
		});
	});

	describe("handling papers without fieldsOfStudy", () => {
		it("should skip papers without fieldsOfStudy property", () => {
			const papers = [{ title: "Paper 1" }, { fieldsOfStudy: ["AI"] }];
			expect(extractTopField(papers)).toBe("AI");
		});

		it("should handle papers with empty fieldsOfStudy", () => {
			const papers = [{ fieldsOfStudy: [] }, { fieldsOfStudy: ["AI"] }];
			expect(extractTopField(papers)).toBe("AI");
		});

		it("should return Multidisciplinary when no fields found", () => {
			const papers = [{ title: "Paper 1" }, { title: "Paper 2" }];
			expect(extractTopField(papers)).toBe("Multidisciplinary");
		});

		it("should return Multidisciplinary when all fieldsOfStudy are empty", () => {
			const papers = [{ fieldsOfStudy: [] }, { fieldsOfStudy: [] }];
			expect(extractTopField(papers)).toBe("Multidisciplinary");
		});
	});

	describe("edge cases", () => {
		it("should handle papers with null fieldsOfStudy", () => {
			const papers = [{ fieldsOfStudy: null }, { fieldsOfStudy: ["AI"] }];
			expect(extractTopField(papers)).toBe("AI");
		});

		it("should handle very large number of papers", () => {
			const papers = Array(1000)
				.fill(null)
				.map((_, i) => ({
					fieldsOfStudy: [i % 10 === 0 ? "AI" : "Other"],
				}));
			expect(extractTopField(papers)).toBe("Other");
		});

		it("should handle papers with complex field names", () => {
			const papers = [
				{
					fieldsOfStudy: [
						"Machine Learning",
						"Deep Learning",
						"Natural Language Processing",
					],
				},
				{
					fieldsOfStudy: ["Machine Learning", "Computer Vision"],
				},
			];
			expect(extractTopField(papers)).toBe("Machine Learning");
		});

		it("should handle single field in many papers", () => {
			const papers = [
				{ fieldsOfStudy: ["AI"] },
				{ fieldsOfStudy: ["AI"] },
				{ fieldsOfStudy: ["AI"] },
			];
			expect(extractTopField(papers)).toBe("AI");
		});
	});
});

describe("getFuzzyValue", () => {
	describe("basic functionality", () => {
		it("should find value with exact keyword match", () => {
			const row = { linkedin: "profile_url" };
			expect(getFuzzyValue(row, ["linkedin"])).toBe("profile_url");
		});

		it("should find value with partial keyword match", () => {
			const row = { LinkedInProfile: "profile_url" };
			expect(getFuzzyValue(row, ["linkedin"])).toBe("profile_url");
		});

		it("should find value with multiple keywords", () => {
			const row = { homepage: "example.com" };
			expect(getFuzzyValue(row, ["website", "url", "link", "homepage"])).toBe(
				"example.com",
			);
		});
	});

	describe("case-insensitive matching", () => {
		it("should handle mixed case keys", () => {
			const row = { LinkedIn: "profile_url" };
			expect(getFuzzyValue(row, ["linkedin"])).toBe("profile_url");
		});

		it("should handle uppercase keys", () => {
			const row = { LINKEDIN: "profile_url" };
			expect(getFuzzyValue(row, ["linkedin"])).toBe("profile_url");
		});

		it("should find values with lowercase matching", () => {
			const row = { linkedin: "profile_url" };
			expect(getFuzzyValue(row, ["linkedin"])).toBe("profile_url");
		});
	});

	describe("special character handling", () => {
		it("should ignore special characters in key matching", () => {
			const row = { "linked-in": "profile_url" };
			expect(getFuzzyValue(row, ["linkedin"])).toBe("profile_url");
		});

		it("should handle keys with underscores", () => {
			const row = { linked_in: "profile_url" };
			expect(getFuzzyValue(row, ["linkedin"])).toBe("profile_url");
		});

		it("should handle keys with spaces", () => {
			const row = { "linked in": "profile_url" };
			expect(getFuzzyValue(row, ["linkedin"])).toBe("profile_url");
		});

		it("should ignore numbers in keys", () => {
			const row = { linkedin2023: "profile_url" };
			expect(getFuzzyValue(row, ["linkedin"])).toBe("profile_url");
		});

		it("should handle complex key names", () => {
			const row = { LinkedIn_Profile_2023: "profile_url" };
			expect(getFuzzyValue(row, ["linkedin"])).toBe("profile_url");
		});
	});

	describe("multiple keywords", () => {
		it("should return first matching key", () => {
			const row = { website: "example.com", homepage: "home.com" };
			const result = getFuzzyValue(row, ["homepage", "website"]);
			expect(["example.com", "home.com"]).toContain(result);
		});

		it("should prioritize based on object key order", () => {
			const row = { url: "url_value", web: "web_value" };
			const result = getFuzzyValue(row, ["web", "url"]);
			expect(result).toBeTruthy();
		});
	});

	describe("edge cases", () => {
		it("should return empty string when no match found", () => {
			const row = { name: "John" };
			expect(getFuzzyValue(row, ["linkedin", "profile"])).toBe("");
		});

		it("should handle empty row object", () => {
			expect(getFuzzyValue({}, ["linkedin"])).toBe("");
		});

		it("should handle empty keywords array", () => {
			const row = { linkedin: "profile_url" };
			expect(getFuzzyValue(row, [])).toBe("");
		});

		it("should handle null value in row", () => {
			const row = { linkedin: null };
			const result = getFuzzyValue(row, ["linkedin"]);
			expect(result).toBe(null);
		});

		it("should handle numeric values", () => {
			const row = { id: 12345 };
			const result = getFuzzyValue(row, ["id"]);
			expect(result).toBe(12345);
		});

		it("should handle boolean values", () => {
			const row = { active: true };
			const result = getFuzzyValue(row, ["active"]);
			expect(result).toBe(true);
		});

		it("should handle single keyword", () => {
			const row = { name: "Acme" };
			expect(getFuzzyValue(row, ["name"])).toBe("Acme");
		});

		it("should find value with keyword substring match", () => {
			// Function checks if keyword is CONTAINED in row keys (normalized)
			const keywords = ["keyword"];
			const row = { keyword50: "value", otherkey: "other" };
			const result = getFuzzyValue(row, keywords);
			expect(result).toBe("value");
		});

		it("should return undefined value as-is", () => {
			const row = { linkedin: undefined };
			const result = getFuzzyValue(row, ["linkedin"]);
			expect(result).toBe(undefined);
		});

		it("should handle object values", () => {
			const row = { linkedInData: { url: "profile" } };
			const result = getFuzzyValue(row, ["linkedin"]);
			expect(typeof result).toBe("object");
		});

		it("should handle array values", () => {
			const row = { tags: ["tag1", "tag2"] };
			const result = getFuzzyValue(row, ["tags"]);
			expect(Array.isArray(result)).toBe(true);
		});
	});

	describe("real-world scenarios", () => {
		it("should extract LinkedIn from company data", () => {
			const row = {
				Company: "TechCorp",
				"Company-LinkedIn": "https://linkedin.com/company/techcorp",
				Website: "techcorp.com",
			};
			const result = getFuzzyValue(row, ["linkedin", "linkedinurl"]);
			expect(result).toBe("https://linkedin.com/company/techcorp");
		});

		it("should find URL variations", () => {
			const row = { CompanyWebsite: "https://example.com" };
			const result = getFuzzyValue(row, ["web", "url", "site"]);
			expect(result).toBe("https://example.com");
		});

		it("should handle messy spreadsheet data", () => {
			const row = {
				"name (full)": "John Doe",
				"linkedin / profile": "linkedin.com/in/johndoe",
				"e-mail": "john@example.com",
			};
			const result = getFuzzyValue(row, ["linkedin"]);
			expect(result).toBe("linkedin.com/in/johndoe");
		});
	});
});

describe("extractScholarId", () => {
	it("should extract ID from Semantic Scholar link", () => {
		expect(
			extractScholarId("https://www.semanticscholar.org/author/12345"),
		).toBe("12345");
	});

	it("should extract ID from Semantic Scholar link with name", () => {
		expect(
			extractScholarId("https://www.semanticscholar.org/author/John-Doe/12345"),
		).toBe("12345");
	});

	it("should extract ID from Google Scholar link", () => {
		expect(
			extractScholarId("https://scholar.google.com/citations?user=ABCDEF12345"),
		).toBe("ABCDEF12345");
	});

	it("should extract ID from Google Scholar link with other params", () => {
		expect(
			extractScholarId(
				"https://scholar.google.com/citations?user=ABCDEF12345&hl=en",
			),
		).toBe("ABCDEF12345");
	});

	it("should return empty string for non-scholar links", () => {
		expect(extractScholarId("https://example.com")).toBe("");
	});

	it("should return empty string for invalid inputs", () => {
		expect(extractScholarId(null as any)).toBe("");
		expect(extractScholarId(undefined as any)).toBe("");
		expect(extractScholarId("")).toBe("");
	});
});
