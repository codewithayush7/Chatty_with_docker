import { upsertStreamUser } from "../lib/stream.js";
import User, { isValidProfilePicUrl } from "../models/User.js";
import { sendEmail } from "../lib/sendEmail.js";
import { generateRawToken, hashToken } from "../lib/token.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

// Constant dummy bcrypt hash (cost 10) to mitigate login timing side channels / account enumeration (SEC-07)
const DUMMY_PASSWORD_HASH =
  "$2b$10$KaCqiscWf0uZMtt6DiXZV.2jBSLdWNRFl0wZ2cHvM7LdnJLpCi9O6";

const COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const isValidEmail = (email) => {
  return typeof email === "string" && EMAIL_REGEX.test(email.trim());
};

export const getAuthCookieOptions = () => ({
  maxAge: COOKIE_MAX_AGE,
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
});

export const setAuthCookie = (res, token) => {
  res.cookie("jwt", token, getAuthCookieOptions());
};

export const clearAuthCookie = (res) => {
  res.clearCookie("jwt", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  });
};


/* ===================== SIGNUP ===================== */
export async function signup(req, res) {
  const { email, password, fullName } = req.body;

  try {
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      typeof fullName !== "string" ||
      !email.trim() ||
      !password ||
      !fullName.trim()
    ) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({
        message: "Email already exists, please use a different one",
      });
    }

    console.log("Creating new user account...");
    const newUser = await User.create({
      email: normalizedEmail,
      fullName: fullName.trim(),
      password,
      isEmailVerified: false,
    });

    newUser.profilePic = `https://api.dicebear.com/6.x/adventurer/svg?seed=${newUser._id}`;

    // Email verification token
    const rawToken = generateRawToken();
    newUser.emailVerificationToken = hashToken(rawToken);
    newUser.emailVerificationTokenExpires = Date.now() + 30 * 60 * 1000; // 30 min
    newUser.lastVerificationEmailSentAt = Date.now();

    await newUser.save();

    // Stream user
    try {
      await upsertStreamUser({
        id: newUser._id.toString(),
        name: newUser.fullName,
        image: newUser.profilePic,
      });
    } catch (err) {
      console.error("Stream user error:", err.message);
    }

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${rawToken}`;

    await sendEmail({
      to: newUser.email,
      subject: "Verify your email - Chatty",
      html: `
        <h2>Welcome to Chatty 👋</h2>
        <p>Please verify your email to continue.</p>
        <a href="${verificationUrl}">Verify Email</a>
        <p>This link expires in 30 minutes.</p>
      `,
    });

    console.log("Signup successful and verification email sent");

    res.status(201).json({
      success: true,
      message: "Signup successful. Please verify your email.",
    });
  } catch (error) {
    console.error("Signup error:", error.message || error);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

/* ===================== LOGIN ===================== */
export async function login(req, res) {
  const { email, password } = req.body;

  try {
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    const user = await User.findOne({ email: normalizedEmail }).select("+password");
    if (!user) {
      // Mitigate login timing side channel by performing constant-round bcrypt comparison
      await bcrypt.compare(password, DUMMY_PASSWORD_HASH);
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: "Please verify your email before logging in",
      });
    }

    // ✅ CREATE JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET_KEY, {
      expiresIn: "7d",
    });

    // ✅ SET COOKIE
    setAuthCookie(res, token);

    const userResponse = user.toObject();
    delete userResponse.password;

    res.status(200).json({
      success: true,
      user: userResponse,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

/* ===================== VERIFY EMAIL ===================== */
export async function verifyEmail(req, res) {
  const token = req.body.token || req.query.token;

  if (typeof token !== "string" || !token.trim()) {
    return res.status(400).json({ message: "Token is required" });
  }

  const cleanToken = token.trim();

  try {
    const hashedToken = hashToken(cleanToken);

    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationTokenExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Token is invalid or expired",
      });
    }

    // ✅ MARK USER AS VERIFIED
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationTokenExpires = undefined;
    user.lastVerificationEmailSentAt = undefined;

    await user.save();

    // ✅ ISSUE JWT
    const jwtToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "7d" },
    );

    // ✅ SET COOKIE
    setAuthCookie(res, jwtToken);

    console.log("User email verified successfully");

    res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    console.error("Email verification error:", error.message || error);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

/* ===================== RESEND VERIFICATION ===================== */
export async function resendVerificationEmail(req, res) {
  const user = req.user;

  if (user.isEmailVerified) {
    return res.status(400).json({ message: "Email already verified" });
  }

  if (
    user.lastVerificationEmailSentAt &&
    Date.now() - user.lastVerificationEmailSentAt < 60 * 1000
  ) {
    return res.status(429).json({
      message: "Please wait before requesting another email",
    });
  }

  const rawToken = generateRawToken();
  user.emailVerificationToken = hashToken(rawToken);
  user.emailVerificationTokenExpires = Date.now() + 30 * 60 * 1000;
  user.lastVerificationEmailSentAt = Date.now();

  await user.save();

  const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${rawToken}`;

  await sendEmail({
    to: user.email,
    subject: "Verify your email - Chatty",
    html: `
      <h2>Email Verification</h2>
      <a href="${verificationUrl}">Verify Email</a>
      <p>Link expires in 30 minutes.</p>
    `,
  });

  res.status(200).json({
    success: true,
    message: "Verification email resent",
  });
}

/* ===================== FORGOT PASSWORD ===================== */
export async function forgotPassword(req, res) {
  const { email } = req.body;

  if (typeof email !== "string" || !email.trim()) {
    return res.status(400).json({ message: "Email is required" });
  }

  const normalizedEmail = email.trim().toLowerCase();
  if (!isValidEmail(normalizedEmail)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  const user = await User.findOne({ email: normalizedEmail });

  if (!user) {
    return res.status(200).json({
      message: "If the email exists, a reset link has been sent",
    });
  }

  const rawToken = generateRawToken();
  user.passwordResetToken = hashToken(rawToken);
  user.passwordResetTokenExpires = Date.now() + 10 * 60 * 1000;

  await user.save();

  const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${rawToken}`;

  await sendEmail({
    to: user.email,
    subject: "Reset your password - Chatty",
    html: `
      <h2>Password Reset</h2>
      <a href="${resetUrl}">Reset Password</a>
      <p>This link expires in 10 minutes.</p>
    `,
  });

  res.status(200).json({
    message: "If the email exists, a reset link has been sent",
  });
}

/* ===================== RESET PASSWORD ===================== */
export async function resetPassword(req, res) {
  const { token, password } = req.body;

  if (
    typeof token !== "string" ||
    typeof password !== "string" ||
    !token.trim() ||
    !password
  ) {
    return res.status(400).json({ message: "Invalid request" });
  }

  if (password.length < 6) {
    return res
      .status(400)
      .json({ message: "Password must be at least 6 characters" });
  }

  const cleanToken = token.trim();

  const user = await User.findOne({
    passwordResetToken: hashToken(cleanToken),
    passwordResetTokenExpires: { $gt: Date.now() },
  });

  if (!user) {
    return res.status(400).json({
      message: "Token is invalid or expired",
    });
  }

  user.password = password;
  user.passwordResetToken = undefined;
  user.passwordResetTokenExpires = undefined;

  await user.save();

  res.status(200).json({
    success: true,
    message: "Password reset successful. Please login.",
  });
}

/* ===================== LOGOUT ===================== */
export function logout(req, res) {
  clearAuthCookie(res);
  res.status(200).json({
    success: true,
    message: "Logout successful",
  });
}

/* ===================== ONBOARD ===================== */
export async function onboard(req, res) {
  try {
    const userId = req.user._id;

    const {
      fullName,
      bio,
      nativeLanguage,
      learningLanguage,
      location,
      profilePic,
    } = req.body;

    if (
      typeof fullName !== "string" ||
      typeof bio !== "string" ||
      typeof nativeLanguage !== "string" ||
      typeof learningLanguage !== "string" ||
      typeof location !== "string" ||
      !fullName.trim() ||
      !bio.trim() ||
      !nativeLanguage.trim() ||
      !learningLanguage.trim() ||
      !location.trim()
    ) {
      return res.status(400).json({
        message: "All fields are required",
        missingFields: [
          (typeof fullName !== "string" || !fullName.trim()) && "fullName",
          (typeof bio !== "string" || !bio.trim()) && "bio",
          (typeof nativeLanguage !== "string" || !nativeLanguage.trim()) && "nativeLanguage",
          (typeof learningLanguage !== "string" || !learningLanguage.trim()) && "learningLanguage",
          (typeof location !== "string" || !location.trim()) && "location",
        ].filter(Boolean),
      });
    }

    const updateData = {
      fullName: fullName.trim(),
      bio: bio.trim(),
      nativeLanguage: nativeLanguage.trim(),
      learningLanguage: learningLanguage.trim(),
      location: location.trim(),
      isOnboarded: true,
    };

    if (profilePic !== undefined) {
      if (typeof profilePic !== "string") {
        return res.status(400).json({ message: "Invalid profile picture URL" });
      }
      const trimmedPic = profilePic.trim();
      if (trimmedPic) {
        if (!isValidProfilePicUrl(trimmedPic)) {
          return res
            .status(400)
            .json({ message: "Invalid profile picture URL" });
        }
        updateData.profilePic = trimmedPic;
      }
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true },
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    try {
      await upsertStreamUser({
        id: updatedUser._id.toString(),
        name: updatedUser.fullName,
        image: updatedUser.profilePic || "",
      });
    } catch (err) {
      console.error("Stream onboarding error:", err.message);
    }

    res.status(200).json({ success: true, user: updatedUser });
  } catch (error) {
    console.error("Onboarding error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
}
