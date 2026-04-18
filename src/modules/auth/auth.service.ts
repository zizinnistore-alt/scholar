import { comparePassword, hashPassword } from "../../utils/password.util.js";
import { ConflictError, UnauthorizedError } from "../../lib/error/index.js";
import { generateToken } from "../../utils/jwt.util.js";
import type { registerSchema } from "./auth.schema.js";
import supabase from "../../lib/db.js";
import type { z } from "zod";

export const authService = {
	async login(email: string, password: string) {
		// 1. Get User
		const { data: user, error } = await supabase
			.from("users")
			.select(
				`id, name, email, password, role, is_approved,
				profile:profiles (university, linkedin_url)`,
			)
			.eq("email", email)
			.single();

		if (error || !user) {
			throw new UnauthorizedError("Invalid credentials 1");
		}

		// 2. Check Password
		const validPassword = await comparePassword(password, user.password);
		if (!validPassword) {
			throw new UnauthorizedError("Invalid credentials 2");
		}

		// 3. Check Approval
		if (user.is_approved === 0) {
			throw new UnauthorizedError("Your account is pending Admin approval.");
		}

		// 4. Fetch Profile Data (for the avatar or extra info)

		// 5. Generate Token
		const token = generateToken({
			id: user.id,
			role: user.role,
			name: user.name,
		});

		return {
			success: true,
			token,
			user: {
				id: user.id,
				name: user.name,
				role: user.role,
				university: user.profile[0]?.university || "",
				linkedin: user.profile[0]?.linkedin_url || "",
			},
		};
	},

	async register(data: z.infer<typeof registerSchema>) {
		const isApproved = data.role === "admin" ? 0 : 1;

		const hashedPassword = await hashPassword(data.personal_info.password);

		// 4. Insert into 'users' table (Auth Credentials)
		const { data: user, error: userError } = await supabase
			.from("users")
			.insert([
				{
					name: data.personal_info.full_name,
					email: data.personal_info.email,
					password: hashedPassword,
					role: data.role,
					is_approved: isApproved,
				},
			])
			.select()
			.single();

		if (userError) {
			console.error("User Register Error:", userError.message);
			if (userError.code === "23505") {
				throw new ConflictError("Email already exists");
			}
			throw new Error("Registration failed.");
		}

		// 5. Insert into 'profiles' table (Detailed Data)
		// We unpack the complex frontend object into specific columns + JSON columns
		const { error: profileError } = await supabase.from("profiles").insert([
			{
				user_id: user.id, // Links to the BIGINT id from users table

				// Specific Columns for Filtering
				full_name: data.personal_info.full_name,
				gender: data.personal_info.gender,
				country: data.personal_info.country,
				governorate: data.personal_info.governorate,

				university: data.education?.university,
				faculty: data.education?.faculty,
				department: data.education?.department,
				graduation_year: data.education?.graduation_year,
				university_email: data.education?.university_email,

				linkedin_url: data.online_presence?.linkedin_url,
				github_url: data.online_presence?.github_url,
				scholar_url: data.online_presence?.scholar_url,

				// JSON Columns for Lists
				skills: data.skills || [],
				experience: data.experience || [],
				internships: data.internships || [],
				courses: data.courses || [],
				personal_projects: data.personal_projects || [],

				// JSON Columns for Objects
				graduation_project: data.graduation_project || {},
				postgraduate_research: data.postgraduate_research || {},
				iti_training: data.iti || {},
				nti_training: data.nti || {},
			},
		]);

		if (profileError) {
			console.error("Profile Error:", profileError.message);
			// Cleanup: Delete the user if profile creation fails so they can try again
			await supabase.from("users").delete().eq("id", user.id);
			throw new Error("Failed to save profile details. Please try again.");
		}

		if (isApproved === 0) {
			return {
				success: true,
				statusCode: 201,
				message: "Account created. Waiting for Admin approval.",
			};
		} else {
			// Generate Token immediately
			const token = generateToken({
				id: user.id,
				role: user.role,
				name: user.name,
			});
			return {
				success: true,
				statusCode: 201,
				message: "Login successful.",
				token,
				user: { id: user.id, name: user.name, role: user.role },
			};
		}
	},
	async logout() {},
};
