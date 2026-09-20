"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = Number(process.env.PORT || 10000);

const ACCESS_KEY =
  process.env.ACCESS_KEY ||
  process.env.ELISY_ACCESS_KEY ||
  "";

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "";

const ADMIN_EMAIL =
  process.env.ADMIN_EMAIL ||
  "";

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD ||
  "";

const ADMIN_JWT_SECRET =
  process.env.ADMIN_JWT_SECRET ||
  JWT_SECRET;

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://frontend-six-jade-97.vercel.app";

const TRADING_ENABLED =
  String(process.env.TRADING_ENABLED || "false").toLowerCase() === "true";

const allowedOrigins = [
  FRONTEND_URL,
  "https://frontend-six-jade-97.vercel.app",
  "http://localhost:5173",
  "http://localhost:3000"
];

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(null, false);
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ]
  })
);

app.use(express.json({ limit: "1mb" }));

/* =========================================================
   HELPERS
   ========================================================= */

function safeEqual(a, b) {
  if (
    typeof a !== "string" ||
    typeof b !== "string"
  ) {
    return false;
  }

  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);

  if (aBuffer.length !== bBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    aBuffer,
    bBuffer
  );
}

function createUserToken() {
  if (!JWT_SECRET) {
    throw new Error(
      "JWT_SECRET is not configured."
    );
  }

  return jwt.sign(
    {
      service: "ELISY254-CLOUD",
      type: "user-access"
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function createAdminToken() {
  if (!ADMIN_JWT_SECRET) {
    throw new Error(
      "ADMIN_JWT_SECRET is not configured."
    );
  }

  return jwt.sign(
    {
      service: "ELISY254-CLOUD",
      type: "admin"
    },
    ADMIN_JWT_SECRET,
    {
      expiresIn: "12h"
    }
  );
}

function authenticateUser(req, res, next) {
  try {
    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        ok: false,
        message: "Authentication required.",
        code: "AUTH_REQUIRED"
      });
    }

    const token =
      authorization
        .substring(7)
        .trim();

    if (!JWT_SECRET) {
      return res.status(503).json({
        ok: false,
        message: "Authentication service is not configured.",
        code: "AUTH_CONFIG_ERROR"
      });
    }

    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch (error) {
    return res.status(401).json({
      ok: false,
      message: "Invalid or expired session.",
      code: "INVALID_TOKEN"
    });
  }
}

function authenticateAdmin(req, res, next) {
  try {
    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        ok: false,
        message: "Admin authentication required.",
        code: "ADMIN_AUTH_REQUIRED"
      });
    }

    const token =
      authorization
        .substring(7)
        .trim();

    if (!ADMIN_JWT_SECRET) {
      return res.status(503).json({
        ok: false,
        message: "Admin authentication is not configured.",
        code: "ADMIN_AUTH_CONFIG_ERROR"
      });
    }

    const decoded = jwt.verify(
      token,
      ADMIN_JWT_SECRET
    );

    if (decoded.type !== "admin") {
      return res.status(403).json({
        ok: false,
        message: "Admin access required.",
        code: "ADMIN_ACCESS_REQUIRED"
      });
    }

    req.admin = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      ok: false,
      message: "Invalid or expired admin session.",
      code: "INVALID_ADMIN_TOKEN"
    });
  }
}

/* =========================================================
   ROOT
   ========================================================= */

app.get("/", (req, res) => {
  res.json({
    ok: true,
    name: "ELISY254 CLOUD",
    status: "online",
    message: "Backend is running"
  });
});

/* =========================================================
   HEALTH
   ========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,

    backend: {
      status: "online"
    },

    trading: {
      enabled: TRADING_ENABLED
    },

    mt5: {
      status: "NOT_CONNECTED"
    },

    timestamp: new Date().toISOString()
  });
});

/* =========================================================
   USER ACCESS KEY
   ========================================================= */

app.post("/api/auth/key", (req, res) => {
  try {
    const suppliedKey =
      typeof req.body?.accessKey === "string"
        ? req.body.accessKey.trim()
        : "";

    if (!ACCESS_KEY) {
      console.error(
        "ACCESS_KEY is missing."
      );

      return res.status(503).json({
        ok: false,
        message:
          "Access service is temporarily unavailable.",
        code:
          "ACCESS_SERVICE_NOT_CONFIGURED"
      });
    }

    if (!suppliedKey) {
      return res.status(400).json({
        ok: false,
        message: "Enter your access key.",
        code: "ACCESS_KEY_REQUIRED"
      });
    }

    if (!safeEqual(
      suppliedKey,
      ACCESS_KEY
    )) {
      return res.status(401).json({
        ok: false,
        message: "Invalid access key.",
        code: "INVALID_ACCESS_KEY"
      });
    }

    const token =
      createUserToken();

    return res.json({
      ok: true,
      message: "Access granted.",
      token,
      user: {
        authenticated: true
      }
    });

  } catch (error) {
    console.error(
      "Access key error:",
      error
    );

    return res.status(503).json({
      ok: false,
      message:
        "Access service is temporarily unavailable.",
      code: "ACCESS_SERVICE_ERROR"
    });
  }
});

/* =========================================================
   USER SESSION
   ========================================================= */

app.get(
  "/api/auth/me",
  authenticateUser,
  (req, res) => {
    res.json({
      ok: true,
      authenticated: true
    });
  }
);

/* =========================================================
   ADMIN LOGIN
   ========================================================= */

app.post("/api/admin/login", (req, res) => {
  try {
    const email =
      typeof req.body?.email === "string"
        ? req.body.email.trim()
        : "";

    const password =
      typeof req.body?.password === "string"
        ? req.body.password
        : "";

    if (
      !ADMIN_EMAIL ||
      !ADMIN_PASSWORD ||
      !ADMIN_JWT_SECRET
    ) {
      console.error(
        "Admin authentication environment variables are missing."
      );

      return res.status(503).json({
        ok: false,
        message:
          "Admin service is temporarily unavailable.",
        code:
          "ADMIN_SERVICE_NOT_CONFIGURED"
      });
    }

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        message:
          "Admin email and password are required.",
        code:
          "ADMIN_CREDENTIALS_REQUIRED"
      });
    }

    const validEmail =
      safeEqual(
        email.toLowerCase(),
        ADMIN_EMAIL.toLowerCase()
      );

    const validPassword =
      safeEqual(
        password,
        ADMIN_PASSWORD
      );

    if (!validEmail || !validPassword) {
      return res.status(401).json({
        ok: false,
        message:
          "Invalid admin credentials.",
        code:
          "INVALID_ADMIN_CREDENTIALS"
      });
    }

    const token =
      createAdminToken();

    return res.json({
      ok: true,
      message: "Admin login successful.",
      token,
      admin: {
        authenticated: true,
        email: ADMIN_EMAIL
      }
    });

  } catch (error) {
    console.error(
      "Admin login error:",
      error
    );

    return res.status(503).json({
      ok: false,
      message:
        "Admin service is temporarily unavailable.",
      code: "ADMIN_LOGIN_ERROR"
    });
  }
});

/* =========================================================
   ADMIN SESSION
   ========================================================= */

app.get(
  "/api/admin/me",
  authenticateAdmin,
  (req, res) => {
    res.json({
      ok: true,
      authenticated: true,
      admin: {
        email: req.admin.email ||
          ADMIN_EMAIL
      }
    });
  }
);

/* =========================================================
   ADMIN DASHBOARD
   ========================================================= */

app.get(
  "/api/admin/dashboard",
  authenticateAdmin,
  (req, res) => {
    res.json({
      ok: true,

      platform: {
        name: "ELISY254 CLOUD",
        status: "online"
      },

      statistics: {
        users: 0,
        connectedMt5: 0,
        activeBots: 0,
        tradesToday: 0,
        failedOrders: 0,
        aiRequests: 0
      },

      mt5: {
        status: "NOT_CONNECTED"
      },

      trading: {
        enabled: TRADING_ENABLED
      },

      timestamp:
        new Date().toISOString()
    });
  }
);

/* =========================================================
   MT5 STATUS
   ========================================================= */

app.get(
  "/api/mt5/status",
  authenticateUser,
  async (req, res) => {
    try {
      const metaApiConfigured =
        Boolean(
          process.env.METAAPI_TOKEN &&
          process.env.METAAPI_ACCOUNT_ID
        );

      if (!metaApiConfigured) {
        return res.json({
          ok: true,
          connected: false,
          status: "NOT_CONNECTED",
          account: null,
          provider: "NONE",
          message:
            "No real MT5 cloud connection is configured."
        });
      }

      return res.json({
        ok: true,
        connected: false,
        status: "NOT_CONNECTED",
        account: null,
        provider: "METAAPI",
        message:
          "MT5 connection has not yet been verified."
      });

    } catch (error) {
      console.error(
        "MT5 status error:",
        error
      );

      return res.status(503).json({
        ok: false,
        connected: false,
        status: "NOT_CONNECTED",
        account: null,
        message:
          "Unable to verify MT5 connection."
      });
    }
  }
);

/* =========================================================
   TRADE
   ========================================================= */

app.post(
  "/api/trade",
  authenticateUser,
  async (req, res) => {
    try {
      if (!TRADING_ENABLED) {
        return res.status(403).json({
          ok: false,
          executed: false,
          message:
            "Real trading is disabled by the server.",
          code:
            "TRADING_DISABLED"
        });
      }

      const side =
        typeof req.body?.side === "string"
          ? req.body.side.toUpperCase()
          : "";

      const symbol =
        typeof req.body?.symbol === "string"
          ? req.body.symbol.trim()
          : "";

      const volume =
        Number(req.body?.volume);

      if (
        side !== "BUY" &&
        side !== "SELL"
      ) {
        return res.status(400).json({
          ok: false,
          executed: false,
          message:
            "Side must be BUY or SELL.",
          code: "INVALID_SIDE"
        });
      }

      if (!symbol) {
        return res.status(400).json({
          ok: false,
          executed: false,
          message:
            "Trading symbol is required.",
          code: "INVALID_SYMBOL"
        });
      }

      if (
        !Number.isFinite(volume) ||
        volume <= 0
      ) {
        return res.status(400).json({
          ok: false,
          executed: false,
          message:
            "Trade volume must be greater than zero.",
          code: "INVALID_VOLUME"
        });
      }

      return res.status(503).json({
        ok: false,
        executed: false,
        message:
          "Real MT5 trading connection is not configured. No order was sent.",
        code:
          "MT5_NOT_CONNECTED"
      });

    } catch (error) {
      console.error(
        "Trade error:",
        error
      );

      return res.status(500).json({
        ok: false,
        executed: false,
        message:
          "Trade request failed.",
        code:
          "TRADE_ERROR"
      });
    }
  }
);

/* =========================================================
   GENERAL STATUS
   ========================================================= */

app.get(
  "/api/status",
  authenticateUser,
  (req, res) => {
    res.json({
      ok: true,
      service:
        "ELISY254 CLOUD",
      backend: "online",

      trading: {
        enabled:
          TRADING_ENABLED
      },

      mt5: {
        configured:
          Boolean(
            process.env.METAAPI_TOKEN &&
            process.env.METAAPI_ACCOUNT_ID
          )
      },

      timestamp:
        new Date().toISOString()
    });
  }
);

/* =========================================================
   404
   ========================================================= */

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message: "API route not found.",
    code: "NOT_FOUND",
    path: req.originalUrl
  });
});

/* =========================================================
   ERROR HANDLER
   ========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      "Unhandled server error:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      ok: false,
      message:
        "Internal server error.",
      code:
        "INTERNAL_ERROR"
    });
  }
);

/* =========================================================
   START
   ========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      "=========================================="
    );

    console.log(
      "       ELISY254 CLOUD BACKEND"
    );

    console.log(
      "=========================================="
    );

    console.log(
      `PORT: ${PORT}`
    );

    console.log(
      `ACCESS_KEY_CONFIGURED: ${Boolean(ACCESS_KEY)}`
    );

    console.log(
      `JWT_SECRET_CONFIGURED: ${Boolean(JWT_SECRET)}`
    );

    console.log(
      `ADMIN_EMAIL_CONFIGURED: ${Boolean(ADMIN_EMAIL)}`
    );

    console.log(
      `ADMIN_PASSWORD_CONFIGURED: ${Boolean(ADMIN_PASSWORD)}`
    );

    console.log(
      `ADMIN_JWT_SECRET_CONFIGURED: ${Boolean(ADMIN_JWT_SECRET)}`
    );

    console.log(
      `TRADING_ENABLED: ${TRADING_ENABLED}`
    );

    console.log(
      "=========================================="
    );
  }
);
