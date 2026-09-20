"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const app = express();

/*
|--------------------------------------------------------------------------
| CONFIG
|--------------------------------------------------------------------------
*/

const PORT = Number(process.env.PORT || 10000);

const JWT_SECRET =
  process.env.JWT_SECRET ||
  process.env.ACCESS_TOKEN_SECRET ||
  "";

const ACCESS_KEY =
  process.env.ACCESS_KEY ||
  process.env.ELISY_ACCESS_KEY ||
  "";

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://frontend-six-jade-97.vercel.app";

const TRADING_ENABLED =
  String(process.env.TRADING_ENABLED || "false").toLowerCase() === "true";

const NODE_ENV =
  process.env.NODE_ENV || "production";

/*
|--------------------------------------------------------------------------
| SECURITY CHECK
|--------------------------------------------------------------------------
*/

if (!JWT_SECRET) {
  console.warn(
    "WARNING: JWT_SECRET is not configured. Authentication tokens cannot be securely created."
  );
}

if (!ACCESS_KEY) {
  console.warn(
    "WARNING: ACCESS_KEY is not configured. /api/auth/key will reject all access attempts."
  );
}

/*
|--------------------------------------------------------------------------
| CORS
|--------------------------------------------------------------------------
*/

const allowedOrigins = [
  FRONTEND_URL,
  "https://frontend-six-jade-97.vercel.app",
  "http://localhost:5173",
  "http://localhost:3000"
].filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      /*
       * Allow requests without an Origin header.
       * Useful for server-to-server requests and health checks.
       */
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      /*
       * Do not crash the backend because of CORS.
       */
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

/*
|--------------------------------------------------------------------------
| BASIC REQUEST LOGGER
|--------------------------------------------------------------------------
*/

app.use((req, res, next) => {
  const started = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - started;

    console.log(
      `${req.method} ${req.originalUrl} -> ${res.statusCode} (${duration}ms)`
    );
  });

  next();
});

/*
|--------------------------------------------------------------------------
| HELPERS
|--------------------------------------------------------------------------
*/

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

  return crypto.timingSafeEqual(aBuffer, bBuffer);
}

function createToken() {
  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not configured.");
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

function authenticate(req, res, next) {
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
      authorization.substring("Bearer ".length).trim();

    if (!token) {
      return res.status(401).json({
        ok: false,
        message: "Authentication token is missing.",
        code: "TOKEN_MISSING"
      });
    }

    if (!JWT_SECRET) {
      return res.status(503).json({
        ok: false,
        message: "Authentication service is not configured.",
        code: "AUTH_CONFIG_ERROR"
      });
    }

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    req.user = decoded;

    next();
  } catch (error) {
    console.error(
      "Authentication error:",
      error.message
    );

    return res.status(401).json({
      ok: false,
      message: "Invalid or expired session.",
      code: "INVALID_TOKEN"
    });
  }
}

/*
|--------------------------------------------------------------------------
| ROOT
|--------------------------------------------------------------------------
*/

app.get("/", (req, res) => {
  res.json({
    ok: true,
    name: "ELISY254 CLOUD",
    status: "online",
    message: "Backend is running"
  });
});

/*
|--------------------------------------------------------------------------
| HEALTH
|--------------------------------------------------------------------------
|
| The frontend uses this endpoint before asking for the access key.
|--------------------------------------------------------------------------
*/

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,

    backend: {
      status: "online",
      environment: NODE_ENV
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

/*
|--------------------------------------------------------------------------
| ACCESS KEY LOGIN
|--------------------------------------------------------------------------
|
| FRONTEND:
|
| POST /api/auth/key
|
| {
|   "accessKey": "YOUR_KEY"
| }
|
|--------------------------------------------------------------------------
*/

app.post("/api/auth/key", (req, res) => {
  try {
    const suppliedKey =
      typeof req.body?.accessKey === "string"
        ? req.body.accessKey.trim()
        : "";

    /*
     * Never reveal whether the configured key exists.
     */
    if (!ACCESS_KEY) {
      console.error(
        "ACCESS_KEY is missing from Render environment variables."
      );

      return res.status(503).json({
        ok: false,
        message: "Access service is temporarily unavailable.",
        code: "ACCESS_SERVICE_NOT_CONFIGURED"
      });
    }

    if (!suppliedKey) {
      return res.status(400).json({
        ok: false,
        message: "Enter your access key.",
        code: "ACCESS_KEY_REQUIRED"
      });
    }

    if (!safeEqual(suppliedKey, ACCESS_KEY)) {
      return res.status(401).json({
        ok: false,
        message: "Invalid access key.",
        code: "INVALID_ACCESS_KEY"
      });
    }

    /*
     * Correct key.
     */
    const token = createToken();

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
      message: "Access service is temporarily unavailable.",
      code: "ACCESS_SERVICE_ERROR"
    });
  }
});

/*
|--------------------------------------------------------------------------
| CURRENT SESSION
|--------------------------------------------------------------------------
*/

app.get(
  "/api/auth/me",
  authenticate,
  (req, res) => {
    res.json({
      ok: true,
      authenticated: true,
      user: {
        type: "access-key-user"
      }
    });
  }
);

/*
|--------------------------------------------------------------------------
| MT5 STATUS
|--------------------------------------------------------------------------
|
| IMPORTANT:
| This route deliberately does NOT claim MT5 is connected unless a real
| integration is configured.
|--------------------------------------------------------------------------
*/

app.get(
  "/api/mt5/status",
  authenticate,
  async (req, res) => {
    try {
      /*
       * At this stage we only report a real connection if the backend
       * has been configured with the necessary integration.
       *
       * We do NOT return fake balance, equity, account number, etc.
       */

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

      /*
       * MetaApi credentials exist.
       *
       * The actual MetaApi account connection should be implemented
       * here when the MetaApi SDK is installed/configured.
       *
       * We still do not fake CONNECTED.
       */

      return res.json({
        ok: true,
        connected: false,
        status: "NOT_CONNECTED",
        account: null,
        provider: "METAAPI",
        message:
          "MetaApi credentials are configured, but the MT5 connection has not been verified by the trading adapter."
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

/*
|--------------------------------------------------------------------------
| REAL TRADE ENDPOINT
|--------------------------------------------------------------------------
|
| This endpoint refuses to pretend that a trade happened.
|
| Until the real MT5/MetaApi adapter is connected, orders are blocked.
|--------------------------------------------------------------------------
*/

app.post(
  "/api/trade",
  authenticate,
  async (req, res) => {
    try {
      if (!TRADING_ENABLED) {
        return res.status(403).json({
          ok: false,
          executed: false,
          message:
            "Real trading is disabled by the server.",
          code: "TRADING_DISABLED"
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

      /*
       * Basic validation.
       */

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

      /*
       * Do not execute anything until a real MT5 adapter is installed.
       */

      return res.status(503).json({
        ok: false,
        executed: false,
        message:
          "Real MT5 trading connection is not configured. No order was sent.",
        code: "MT5_NOT_CONNECTED"
      });

    } catch (error) {
      console.error(
        "Trade endpoint error:",
        error
      );

      return res.status(500).json({
        ok: false,
        executed: false,
        message:
          "Trade request failed. No order confirmation was returned.",
        code: "TRADE_ERROR"
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| SERVER INFO
|--------------------------------------------------------------------------
*/

app.get(
  "/api/status",
  authenticate,
  (req, res) => {
    res.json({
      ok: true,
      service: "ELISY254 CLOUD",
      backend: "online",

      trading: {
        enabled: TRADING_ENABLED
      },

      mt5: {
        configured: Boolean(
          process.env.METAAPI_TOKEN &&
          process.env.METAAPI_ACCOUNT_ID
        )
      },

      timestamp: new Date().toISOString()
    });
  }
);

/*
|--------------------------------------------------------------------------
| 404
|--------------------------------------------------------------------------
*/

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message: "API route not found.",
    code: "NOT_FOUND",
    path: req.originalUrl
  });
});

/*
|--------------------------------------------------------------------------
| GLOBAL ERROR HANDLER
|--------------------------------------------------------------------------
*/

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
      message: "Internal server error.",
      code: "INTERNAL_ERROR"
    });
  }
);

/*
|--------------------------------------------------------------------------
| START
|--------------------------------------------------------------------------
*/

app.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("==========================================");
  console.log("       ELISY254 CLOUD BACKEND");
  console.log("==========================================");
  console.log(`PORT: ${PORT}`);
  console.log(`ENVIRONMENT: ${NODE_ENV}`);
  console.log(
    `TRADING_ENABLED: ${TRADING_ENABLED}`
  );
  console.log(
    `ACCESS_KEY_CONFIGURED: ${Boolean(ACCESS_KEY)}`
  );
  console.log(
    `JWT_SECRET_CONFIGURED: ${Boolean(JWT_SECRET)}`
  );
  console.log(
    `METAAPI_CONFIGURED: ${Boolean(
      process.env.METAAPI_TOKEN &&
      process.env.METAAPI_ACCOUNT_ID
    )}`
  );
  console.log("==========================================");
  console.log("");
});
