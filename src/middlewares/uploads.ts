import multer from "multer";
import { createFileFilter } from "../config/multer.js";

const uploadAvatar = multer({
	storage: multer.memoryStorage(),
	limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
	fileFilter: createFileFilter(["image/png", "image/jpeg", "image/jpg"]),
});

const uploadCV = multer({
	storage: multer.memoryStorage(),
	limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
	fileFilter: createFileFilter(["application/pdf", "application/msword"]),
});

const uploadExcel = multer({
	storage: multer.memoryStorage(),
	limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
	fileFilter: createFileFilter([
		"application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	]),
});

export { uploadAvatar, uploadCV, uploadExcel };
