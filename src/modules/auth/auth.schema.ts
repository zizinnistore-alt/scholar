import { z } from "zod";

export const loginSchema = z.object({
	email: z.email(),
	password: z.string(),
});

const personalInfoSchema = z.object({
	email: z.email(),
	password: z.string(),
	full_name: z.string(),
	gender: z.string(),
	country: z.string(),
	governorate: z.string(),
});

const educationSchema = z.object({
	university: z.string().optional(),
	faculty: z.string().optional(),
	department: z.string().optional(),
	graduation_year: z.number().optional(),
	university_email: z.string().optional(),
});

const onlinePresenceSchema = z.object({
	linkedin_url: z.string().optional(),
	github_url: z.string().optional(),
	scholar_url: z.string().optional(),
});

export const registerSchema = z.object({
	role: z.enum(["student", "graduate", "industry", "admin"]).default("student"),
	personal_info: personalInfoSchema,
	education: educationSchema.optional(),
	online_presence: onlinePresenceSchema.optional(),

	skills: z.array(z.string()).default([]),
	internships: z.array(z.string()).default([]),
	courses: z.array(z.string()).default([]),
	personal_projects: z.array(z.string()).default([]),

	graduation_project: z.record(z.string(), z.unknown()).default({}),
	postgraduate_research: z.record(z.string(), z.unknown()).default({}),
	experience: z.record(z.string(), z.unknown()).default({}),
	iti: z.record(z.string(), z.unknown()).default({}),
	nti: z.record(z.string(), z.unknown()).default({}),
});
