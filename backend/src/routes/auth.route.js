import express from "express";
import {
  login,
  logout,
  onboard,
  signup,
  verifyEmail,
  resendVerificationEmail,
  forgotPassword,
  resetPassword,
} from "../controllers/auth.controller.js";
import { protectRoute, verifiedOnly } from "../middleware/auth.middleware.js";
import {
  signupLimiter,
  loginLimiter,
  forgotPasswordLimiter,
  verifyEmailLimiter,
  resendVerificationLimiter,
  resetPasswordLimiter,
} from "../middleware/rateLimiter.middleware.js";

const router = express.Router();

router.post("/signup", signupLimiter, signup);
router.post("/verify-email", verifyEmailLimiter, verifyEmail);
router.post(
  "/resend-verification",
  protectRoute,
  resendVerificationLimiter,
  resendVerificationEmail,
);
router.post("/login", loginLimiter, login);
router.post("/forgot-password", forgotPasswordLimiter, forgotPassword);
router.post("/reset-password", resetPasswordLimiter, resetPassword);
router.post("/logout", logout);
router.post("/onboarding", protectRoute, verifiedOnly, onboard);

router.get("/me", protectRoute, (req, res) => {
  res.status(200).json({ success: true, user: req.user });
});

export default router;
