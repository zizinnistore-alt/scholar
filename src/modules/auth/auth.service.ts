import bcrypt from "bcryptjs";
import supabase from "../../lib/db.js";
import { UnauthorizedError } from "../../lib/error/index.js";
import { generateToken } from "../../utils/jwt.utli.js";

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
		const validPassword = await bcrypt.compare(password, user.password);
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
	async register(email: string, password: string) {},
	async logout() {},
};
