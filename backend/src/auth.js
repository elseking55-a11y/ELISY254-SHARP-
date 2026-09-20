import crypto from "crypto";
import jwt from "jsonwebtoken";

function getJwtSecret() {
  const secret = String(process.env.JWT_SECRET || "").trim();

  if (!secret) {
    throw new Error("JWT_SECRET is not configured");
  }

  return secret;
}

export function hashKey(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

export function createToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      role: user.role
    },
    getJwtSecret(),
    {
      expiresIn: "12h"
    }
  );
}

export function createAdminToken() {
  return jwt.sign(
    {
      sub: "admin",
      role: "ADMIN"
    },
    getJwtSecret(),
    {
      expiresIn: "12h"
    }
  );
}

export function verifyToken(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        ok: false,
        code: "AUTH_REQUIRED",
        message: "Authentication required"
      });
    }

    const token = header.slice(7);

    const decoded = jwt.verify(
      token,
      getJwtSecret()
    );

    req.user = decoded;

    next();
  } catch {
    return res.status(401).json({
      ok: false,
      code: "SESSION_EXPIRED",
      message: "Session expired. Please sign in again."
    });
  }
}

export function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "ADMIN") {
    return res.status(403).json({
      ok: false,
      code: "ADMIN_REQUIRED",
      message: "Administrator access required."
    });
  }

  next();
      }
