import rateLimit from "express-rate-limit";

/**
 * Architecture & Store Note:
 * This uses the default in-memory MemoryStore, which is suitable for the current
 * single-container architecture running on AWS EC2 via docker-compose.
 *
 * Limitation:
 * If the application is horizontally scaled across multiple container instances
 * in the future, rate-limit state will not be shared across replicas. A centralized
 * distributed store (e.g. rate-limit-redis) would be required at that stage.
 */

// 1. Login Limiter: 10 attempts per 15 minutes per IP
// Mitigates credential stuffing and brute force while allowing typos
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    message: "Too many login attempts. Please try again after 15 minutes.",
  },
});

// 2. Signup Limiter: 5 accounts per 1 hour per IP
// Mitigates mass automated bot account creation and Brevo verification email exhaustion
export const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    message: "Too many accounts created from this IP. Please try again after an hour.",
  },
});

// 3. Forgot Password Limiter: 5 requests per 15 minutes per IP
// Prevents email-bombing victim addresses and exhausting Brevo quota
export const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    message: "Too many password reset requests. Please try again after 15 minutes.",
  },
});

// 4. Resend Verification Limiter: 5 requests per 15 minutes per IP
// Complements DB-level cooldown to stop automated email flooding
export const resendVerificationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    message: "Too many verification requests. Please try again after 15 minutes.",
  },
});

// 5. Verify Email Limiter: 15 requests per 15 minutes per IP
// Allows client reloads and retries while blocking high-throughput token guessing
export const verifyEmailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    message: "Too many verification attempts. Please try again after 15 minutes.",
  },
});

// 6. Reset Password Limiter: 10 requests per 15 minutes per IP
// Protects token consumption and brute force during password submission
export const resetPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    message: "Too many password reset attempts. Please try again after 15 minutes.",
  },
});
