import supabase from "../../lib/db.js";
import type { PaginationQuery } from "../../middlewares/pagination.js";
import * as xlsx from "xlsx";
import axios from "axios";
import env from "../../config/env.js";
import {
	cleanName,
	extractScholarId,
	extractTopField,
} from "../../utils/extractors.js";
import type { FilterQuery, UploadOptions } from "./researchers.schema.js";

const researchersService = {
	async getMainTopics() {
		const { data, error } = await supabase
			.from("unique_main_topics")
			.select("main_topic");
		if (error) throw error;
		// const topics = [
		// 	...new Set(
		// 		data.map((r) => r.main_topic).filter((t) => t && t.trim() !== ""),
		// 	),
		// ];
		return data.map((t: { main_topic: string }) => t.main_topic) ?? [];
	},

	async getResearchers(pagination: PaginationQuery, filters: FilterQuery) {
		const { page, limit, sortBy, sortOrder } = pagination;

		const { data, error } = await supabase.rpc("get_unique_researchers", {
			p_main_topic: filters.main_topic || null,
			p_subtopic: filters.subtopic || null,
			p_university: filters.university || null,
			p_researcher: filters.researcher || null,
			p_keywords: filters.keywords || null,
			p_limit: limit,
			p_offset: (page - 1) * limit,
			p_sort_by: sortBy || "name",
			p_sort_order: sortOrder || "asc",
		});

		if (error) throw error;
		return data ?? [];
	},

	async getResearchersDashboard() {
		const { data, error } = await supabase
			.from("researcher_stats_summary")
			.select("*")
			.single();
		if (error) throw error;
		console.log("Dashboard Stats:", data);
		return data || {};
	},

	async uploadResearchers(buffer: Buffer, options: UploadOptions) {
		const { clear_db, main_topic } = options;
		const workbook = xlsx.read(buffer, { type: "buffer" });

		if (clear_db) {
			const { error: deleteError } = await supabase
				.from("academic_researchers")
				.delete()
				.neq("id", 0);
			if (deleteError) throw deleteError;
		}

		let researchersToInsert: any[] = [];
		const sheetsEntries = Object.entries(workbook.Sheets);

		sheetsEntries.forEach(([sheetName, sheet]) => {
			const rows: any[][] = xlsx.utils.sheet_to_json(sheet, { header: 1 });

			for (let i = 1; i < rows.length; i++) {
				const cols = rows[i];
				if (!cols || cols.length === 0) continue;

				const name = String(cols[0] || "");
				const affil = String(cols[1] || "");
				const subtopics = String(cols[2] || "");
				const link = String(cols[3] || "");

				if (
					!name ||
					name.trim() === "" ||
					name.toLowerCase().includes("name")
				) {
					continue;
				}

				const scholar_id = extractScholarId(link);
				const topicToSave =
					sheetName && sheetName !== "Sheet1"
						? sheetName.trim()
						: main_topic || "Uncategorized";

				researchersToInsert.push({
					name: name.trim(),
					affiliation: affil.trim(),
					main_topic: topicToSave,
					subtopics: subtopics.trim(),
					scholar_id,
				});
			}
		});

		if (researchersToInsert.length > 0) {
			const { error: insertError } = await supabase
				.from("academic_researchers")
				.insert(researchersToInsert);
			if (insertError) throw insertError;
		}

		return researchersToInsert.length;
	},

	async analyzeResearcher(id: number) {
		const { data: localData, error } = await supabase
			.from("academic_researchers")
			.select("*")
			.eq("id", id)
			.single();

		if (error || !localData) {
			throw new Error("Researcher not found in local DB");
		}

		let s2AuthorData = null;
		let authorIdToFetch = null;
		const storedId = localData.scholar_id || "";

		if (/^\d+$/.test(storedId)) {
			authorIdToFetch = storedId;
		} else {
			// Smart Name Search
			let cleanQueryName = cleanName(localData.name);

			const searchRes = await axios
				.get(`https://api.semanticscholar.org/graph/v1/author/search`, {
					params: { query: cleanQueryName, limit: 1, fields: "authorId" },
					headers: { "x-api-key": env.S2_API_KEY || "" },
				})
				.catch(() => null);

			if (searchRes?.data?.data && searchRes.data.data.length > 0) {
				authorIdToFetch = searchRes.data.data[0].authorId;
			}
		}

		if (authorIdToFetch) {
			const resData = await axios
				.get(
					`https://api.semanticscholar.org/graph/v1/author/${authorIdToFetch}`,
					{
						params: {
							fields:
								"name,citationCount,hIndex,paperCount,url,papers.title,papers.year,papers.venue,papers.citationCount,papers.fieldsOfStudy,papers.authors,papers.url",
						},
						headers: { "x-api-key": env.S2_API_KEY || "" },
					},
				)
				.catch(() => null);

			if (resData?.data) {
				s2AuthorData = resData.data;
				s2AuthorData.primaryField = extractTopField(s2AuthorData.papers);
			}
		}

		let collaborators: any[] = [];
		if (s2AuthorData?.papers) {
			const collabMap = new Map();
			s2AuthorData.papers.forEach((p: any) => {
				if (p.authors) {
					p.authors.forEach((a: any) => {
						if (a.authorId !== s2AuthorData.authorId && a.name) {
							if (!collabMap.has(a.authorId)) {
								collabMap.set(a.authorId, {
									name: a.name,
									id: a.authorId,
									count: 0,
								});
							}
							collabMap.get(a.authorId).count++;
						}
					});
				}
			});

			collaborators = Array.from(collabMap.values())
				.sort((a, b) => b.count - a.count)
				.slice(0, 10);
		}

		return {
			local: localData,
			author: s2AuthorData,
			collaborators: collaborators,
		};
	},
};

export default researchersService;
