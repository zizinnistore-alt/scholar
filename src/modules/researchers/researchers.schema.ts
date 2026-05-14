import { z } from "zod";

export const FilterQuerySchema = z.object({
	main_topic: z.string().optional(),
	subtopic: z.string().optional(),
	university: z.string().optional(),
	researcher: z.string().optional(),
	keywords: z.string().optional(),
});

export const UploadOptionsSchema = z.object({
	clear_db: z
		.string()
		.optional()
		.transform((val) => val === "true")
		.default(false),
	main_topic: z.string().optional(),
});

export const AnalyzeRequestSchema = z.object({
	id: z.union([z.number(), z.string()]).transform(Number),
});

export const ResearcherSchema = z.object({
	id: z.number().optional(),
	name: z.string(),
	affiliation: z.string().optional(),
	main_topic: z.string(),
	subtopics: z.string().optional(),
	scholar_id: z.string().optional(),
	titles: z.string().optional(),
});

export type FilterQuery = z.infer<typeof FilterQuerySchema>;
export type UploadOptions = z.infer<typeof UploadOptionsSchema>;
export type AnalyzeRequest = z.infer<typeof AnalyzeRequestSchema>;
export type Researcher = z.infer<typeof ResearcherSchema>;
