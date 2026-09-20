import crypto from "crypto";
import jwt from "jsonwebtoken";

function hashKey(value) {
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
    process.env.JWT_SECRET,
    {
      expiresIn: "12h"
    }
  );
}

export function verifyToken(req, res, next) {
  try {
    const header =
      req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        ok: false,
        message: "Authentication required"
      });
    }

    const token = header.slice(7);

    const decoded =
      jwt.verify(
        token,
        process.env.JWT_SECRET
      );

    req.user = decoded;

    next();
  } catch {
    return res.status(401).json({
      ok: false,
      message: "Invalid or expired session"
    });
  }
}

export { hashKey };
