import express from "express";
import { protectRoute, verifiedOnly } from "../middleware/auth.middleware.js";
import { getStreamToken } from "../controllers/chat.controller.js";

const router = express.Router();

router.get("/token", protectRoute, verifiedOnly, getStreamToken);

export default router;