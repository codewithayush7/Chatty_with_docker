import { upsertStreamUser } from "../lib/stream.js";
import User from "../models/User.js";
import { sendEmail } from "../lib/sendEmail.js";
import { generateRawToken, hashToken } from "../lib/token.js";
import jwt from "jsonwebtoken";

/* ===================== SIGNUP ===================== */
export async function signup(req, res) {
  console.log("\n========== SIGNUP CALLED ==========");
  console.log("Request body:", req.body);

  const { email, password, fullName } = req.body;

  try {
    if (!email || !password || !fullName) {
      console.log("❌ Missing fields");
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 6) {
      console.log("❌ Password too short");
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.log("❌ Invalid email format");
      return res.status(400).json({ message: "Invalid email format" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log("❌ Email already exists");
      return res.status(400).json({
        message: "Email already exists, please use a different one",
      });
    }

    console.log("✅ Creating new user...");
    const newUser = await User.create({
      email,
      fullName,
      password,
      isEmailVerified: false,
    });

    newUser.profilePic = `https://api.dicebear.com/6.x/adventurer/svg?seed=${newUser._id}`;

    // Email verification token
    const rawToken = generateRawToken();
    console.log("📧 Generated raw token:", rawToken);

    newUser.emailVerificationToken = hashToken(rawToken);
    console.log("🔐 Hashed token:", newUser.emailVerificationToken);

    newUser.emailVerificationTokenExpires = Date.now() + 30 * 60 * 1000; // 30 min
    newUser.lastVerificationEmailSentAt = Date.now();

    await newUser.save();
    console.log("✅ User saved to database");

    // Stream user
    try {
      await upsertStreamUser({
        id: newUser._id.toString(),
        name: newUser.fullName,
        image: newUser.profilePic,
      });
      console.log("✅ Stream user created");
    } catch (err) {
      console.error("❌ Stream user error:", err.message);
    }

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${rawToken}`;
    console.log("📧 Verification URL:", verificationUrl);

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

    console.log("✅ Email sent successfully");
    console.log("========================================\n");

    res.status(201).json({
      success: true,
      message: "Signup successful. Please verify your email.",
    });
  } catch (error) {
    console.error("❌ Signup error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

/* ===================== LOGIN ===================== */
export async function login(req, res) {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
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

    // ✅ SET COOKIE (THIS WAS MISSING)
    res.cookie("jwt", token, {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: "lax",
      secure: false,
    });

    res.status(200).json({
      success: true,
      user,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

/* ===================== VERIFY EMAIL ===================== */
/* ===================== VERIFY EMAIL ===================== */
export async function verifyEmail(req, res) {
  const token = req.body.token || req.query.token;

  console.log("\n========== VERIFY EMAIL CALLED ==========");
  console.log("Raw token received:", token);
  console.log("Token length:", token?.length);

  if (!token) {
    console.log("❌ No token provided");
    return res.status(400).json({ message: "Token is required" });
  }

  try {
    const hashedToken = hashToken(token);
    console.log("Hashed token:", hashedToken);

    // First, let's see ALL users with verification tokens
    const allUsersWithTokens = await User.find({
      emailVerificationToken: { $exists: true, $ne: null },
    }).select("email emailVerificationToken emailVerificationTokenExpires");

    console.log("\n📋 All users with verification tokens:");
    allUsersWithTokens.forEach((u) => {
      console.log(`  - ${u.email}`);
      console.log(`    Token: ${u.emailVerificationToken}`);
      console.log(`    Expires: ${new Date(u.emailVerificationTokenExpires)}`);
      console.log(
        `    Match: ${u.emailVerificationToken === hashedToken ? "✅ YES" : "❌ NO"}`,
      );
    });

    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationTokenExpires: { $gt: Date.now() },
    });

    console.log("\n🔍 Query result:");
    console.log("User found:", user ? `YES - ${user.email}` : "NO");

    if (!user) {
      console.log("❌ No matching user found");
      return res.status(400).json({
        message: "Token is invalid or expired",
      });
    }

    console.log("\n📝 Before update:");
    console.log("  isEmailVerified:", user.isEmailVerified);

    // ✅ MARK USER AS VERIFIED
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationTokenExpires = undefined;
    user.lastVerificationEmailSentAt = undefined;

    await user.save();

    console.log("\n📝 After save:");
    console.log("  isEmailVerified:", user.isEmailVerified);

    // Double check in DB
    const verifyInDb = await User.findById(user._id);
    console.log("\n📝 DB verification:");
    console.log("  isEmailVerified:", verifyInDb.isEmailVerified);

    // ✅ ISSUE JWT
    const jwtToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "7d" },
    );

    // ✅ SET COOKIE
    res.cookie("jwt", jwtToken, {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      secure: process.env.NODE_ENV === "production",
    });

    console.log("\n✅ SUCCESS - Cookie set, responding");
    console.log("========================================\n");

    res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    console.error("\n❌ ERROR:", error);
    console.log("========================================\n");
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

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  const user = await User.findOne({ email });

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

  if (!token || !password) {
    return res.status(400).json({ message: "Invalid request" });
  }

  if (password.length < 6) {
    return res
      .status(400)
      .json({ message: "Password must be at least 6 characters" });
  }

  const user = await User.findOne({
    passwordResetToken: hashToken(token),
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
  res.clearCookie("jwt");
  res.status(200).json({
    success: true,
    message: "Logout successful",
  });
}

/* ===================== ONBOARD ===================== */
export async function onboard(req, res) {
  try {
    const userId = req.user._id;

    const { fullName, bio, nativeLanguage, learningLanguage, location } =
      req.body;

    if (
      !fullName ||
      !bio ||
      !nativeLanguage ||
      !learningLanguage ||
      !location
    ) {
      return res.status(400).json({
        message: "All fields are required",
        missingFields: [
          !fullName && "fullName",
          !bio && "bio",
          !nativeLanguage && "nativeLanguage",
          !learningLanguage && "learningLanguage",
          !location && "location",
        ].filter(Boolean),
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        ...req.body,
        isOnboarded: true,
      },
      { new: true },
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
