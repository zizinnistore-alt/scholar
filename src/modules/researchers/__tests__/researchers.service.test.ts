import { describe, it, expect, vi, beforeEach } from "vitest";
import researchersService from "../researchers.service.js";
import supabase from "../../../lib/db.js";
import axios from "axios";

vi.mock("../../../lib/db.js", () => ({
	default: {
		from: vi.fn(() => ({
			select: vi.fn(() => ({
				eq: vi.fn(() => ({
					single: vi.fn(() => Promise.resolve({ data: null, error: null })),
				})),
			})),
			delete: vi.fn(() => ({
				neq: vi.fn(() => Promise.resolve({ error: null })),
			})),
			insert: vi.fn(() => Promise.resolve({ error: null })),
		})),
		rpc: vi.fn(() => Promise.resolve({ data: [], error: null })),
	},
}));

vi.mock("axios");

describe("researchersService", () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	describe("getMainTopics", () => {
		it("should fetch unique main topics", async () => {
			const mockTopics = [{ main_topic: "Topic 1" }, { main_topic: "Topic 2" }];
			(supabase.from as any).mockReturnValue({
				select: vi.fn().mockResolvedValue({ data: mockTopics, error: null }),
			});

			const topics = await researchersService.getMainTopics();

			expect(topics).toEqual(["Topic 1", "Topic 2"]);
			expect(supabase.from).toHaveBeenCalledWith("unique_main_topics");
		});

		it("should throw error if fetching fails", async () => {
			(supabase.from as any).mockReturnValue({
				select: vi
					.fn()
					.mockResolvedValue({ data: null, error: new Error("DB Error") }),
			});

			await expect(researchersService.getMainTopics()).rejects.toThrow(
				"DB Error",
			);
		});
	});

	describe("getResearchers", () => {
		it("should call get_unique_researchers RPC", async () => {
			const mockData = [{ id: 1, name: "Researcher 1" }];
			(supabase.rpc as any).mockResolvedValue({ data: mockData, error: null });

			const pagination = {
				limit: 10,
				offset: 0,
				page: 1,
				sortBy: "id",
				sortOrder: "asc" as const,
			};
			const filters = { main_topic: "Topic 1" };

			const result = await researchersService.getResearchers(
				pagination,
				filters,
			);

			expect(result).toEqual(mockData);
			expect(supabase.rpc).toHaveBeenCalledWith(
				"get_unique_researchers",
				expect.objectContaining({
					p_main_topic: "Topic 1",
					p_limit: 10,
					p_offset: 0,
				}),
			);
		});
	});

	describe("analyzeResearcher", () => {
		it("should throw error if researcher not found locally", async () => {
			(supabase.from as any).mockReturnValue({
				select: vi.fn().mockReturnThis(),
				eq: vi.fn().mockReturnThis(),
				single: vi
					.fn()
					.mockResolvedValue({ data: null, error: new Error("Not found") }),
			});

			await expect(researchersService.analyzeResearcher(1)).rejects.toThrow(
				"Researcher not found in local DB",
			);
		});

		it("should resolve ID and fetch from S2 API", async () => {
			const mockLocalData = { id: 1, name: "John Doe", scholar_id: "12345" };
			(supabase.from as any).mockReturnValue({
				select: vi.fn().mockReturnThis(),
				eq: vi.fn().mockReturnThis(),
				single: vi.fn().mockResolvedValue({ data: mockLocalData, error: null }),
			});

			const mockS2Data = {
				authorId: "12345",
				name: "John Doe",
				papers: [
					{
						title: "Paper 1",
						authors: [
							{ authorId: "12345", name: "John Doe" },
							{ authorId: "67890", name: "Jane Smith" },
						],
					},
				],
			};
			(axios.get as any).mockResolvedValue({ data: mockS2Data });

			const result = await researchersService.analyzeResearcher(1);

			expect(result.local).toEqual(mockLocalData);
			expect(result.author.authorId).toBe("12345");
			expect(result.collaborators).toHaveLength(1);
			expect(result.collaborators[0].name).toBe("Jane Smith");
		});
	});
});
