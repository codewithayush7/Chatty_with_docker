import mongoose from "mongoose";
import bcrypt from "bcryptjs";

export const ALLOWED_PROFILE_PIC_HOSTS = new Set([
  "api.dicebear.com",
  "avatar.iran.liara.run",
]);

export const isValidProfilePicUrl = (urlStr) => {
  if (typeof urlStr !== "string") return false;
  const trimmed = urlStr.trim();
  if (!trimmed) return false;

  try {
    const parsed = new URL(trimmed);

    // Protocol must strictly be HTTPS
    if (parsed.protocol !== "https:") {
      return false;
    }

    // Credentials / userinfo disallowed
    if (parsed.username || parsed.password) {
      return false;
    }

    // Custom ports disallowed (default port 443 or none)
    if (parsed.port && parsed.port !== "443") {
      return false;
    }

    // Host must match trusted allowlist
    const hostname = parsed.hostname.toLowerCase();
    if (!ALLOWED_PROFILE_PIC_HOSTS.has(hostname)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
};

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
      select: false,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    emailVerificationToken: String,
    emailVerificationTokenExpires: Date,
    passwordResetToken: String,
    passwordResetTokenExpires: Date,
    lastVerificationEmailSentAt: Date,
    passwordChangedAt: Date,

    bio: {
      type: String,
      default: "",
    },
    profilePic: {
      type: String,
      default: "",
      validate: {
        validator: function (v) {
          if (!v || v === "") return true;
          return isValidProfilePicUrl(v);
        },
        message: "Invalid profile picture URL",
      },
    },
    nativeLanguage: {
      type: String,
      default: "",
    },
    learningLanguage: {
      type: String,
      default: "",
    },
    location: {
      type: String,
      default: "",
    },
    isOnboarded: {
      type: Boolean,
      default: false,
    },
    friends: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
  },
  { timestamps: true },
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);

    // Invalidate old JWTs
    if (!this.isNew) {
      this.passwordChangedAt = Date.now() - 1000;
    }

    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.matchPassword = async function (enteredPassword) {
  const isPasswordCorrect = await bcrypt.compare(
    enteredPassword,
    this.password,
  );
  return isPasswordCorrect;
};

const User = mongoose.model("User", userSchema);

export default User;
