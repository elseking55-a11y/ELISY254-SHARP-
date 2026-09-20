import "dotenv/config";

import express from "express";
import cors from "cors";
import helmet from "helmet";
import crypto from "crypto";

import { query } from "./db.js";
import {
  createToken,
  createAdminToken,
  verifyToken,
  requireAdmin,
  hashKey
} from "./auth.js";

import {
  getConnectionStatus,
  getAccountInformation,
  getPositions,
  createMarketOrder
} from "./mt5.js";

const app = express();

const PORT = Number(process.env.PORT || 10000);

const FRONTEND_ORIGIN = String(
  process.env.FRONTEND_ORIGIN || ""
).trim();

app.use(
  cors({
    origin: FRONTEND_ORIGIN || true,
    credentials: true
  })
);

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

app.use(express.json({ limit: "1mb" }));

/* =========================================================
   BASIC
========================================================= */

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "ELISY254 CLOUD",
    message: "Backend is running"
  });
});

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", async (req, res) => {
  let database = "offline";

  try {
    await query("SELECT 1");
    database = "online";
  } catch {
    database = "offline";
  }

  const mt5 = getConnectionStatus();

  res.json({
    ok: true,
    service: "ELISY254 CLOUD",

    backend: {
      status: "online"
    },

    database,

    mt5,

    trading: {
      enabled:
        String(process.env.TRADING_ENABLED || "false").toLowerCase() ===
        "true",
      status:
        String(process.env.TRADING_ENABLED || "false").toLowerCase() ===
        "true"
          ? "ENABLED"
          : "DISABLED"
    }
  });
});

/* =========================================================
   ACCESS KEY
========================================================= */

app.post("/api/auth/key", async (req, res) => {
  try {
    const accessKey = String(
      req.body?.accessKey || ""
    ).trim();

    if (!accessKey) {
      return res.status(400).json({
        ok: false,
        code: "ACCESS_KEY_REQUIRED",
        message: "Enter your access key."
      });
    }

    const configuredKey = String(
      process.env.ELISY_ACCESS_KEY || ""
    ).trim();

    if (!configuredKey) {
      console.error("ELISY_ACCESS_KEY is missing on Render.");

      return res.status(503).json({
        ok: false,
        code: "ACCESS_SYSTEM_NOT_CONFIGURED",
        message: "Access system is not configured yet."
      });
    }

    const suppliedHash = hashKey(accessKey);
    const configuredHash = hashKey(configuredKey);

    const suppliedBuffer = Buffer.from(suppliedHash);
    const configuredBuffer = Buffer.from(configuredHash);

    if (
      suppliedBuffer.length !== configuredBuffer.length ||
      !crypto.timingSafeEqual(
        suppliedBuffer,
        configuredBuffer
      )
    ) {
      return res.status(401).json({
        ok: false,
        code: "ACCESS_KEY_INVALID",
        message: "The access key is incorrect."
      });
    }

    /*
      The key is valid.

      We create/reuse the platform user automatically.
      The actual MT5 account is NOT created here.
    */

    let result = await query(
      `
      SELECT id, email, role, status
      FROM users
      WHERE access_key_hash = $1
      LIMIT 1
      `,
      [suppliedHash]
    );

    let user;

    if (result.rows.length > 0) {
      user = result.rows[0];

      if (user.status !== "ACTIVE") {
        return res.status(403).json({
          ok: false,
          code: "USER_DISABLED",
          message: "This account is disabled."
        });
      }
    } else {
      const userId = crypto.randomUUID();

      result = await query(
        `
        INSERT INTO users (
          id,
          email,
          access_key_hash,
          role,
          status
        )
        VALUES ($1, $2, $3, 'USER', 'ACTIVE')
        RETURNING id, email, role, status
        `,
        [
          userId,
          null,
          suppliedHash
        ]
      );

      user = result.rows[0];

      await query(
        `
        INSERT INTO risk_settings (
          user_id
        )
        VALUES ($1)
        ON CONFLICT (user_id) DO NOTHING
        `,
        [user.id]
      );
    }

    const token = createToken(user);

    return res.json({
      ok: true,
      message: "Access verified.",
      token,

      user: {
        id: user.id,
        role: user.role,
        status: user.status
      },

      mt5: {
        status: "NOT_CONNECTED",
        realConnectionRequired: true
      },

      trading: {
        status: "DISABLED"
      }
    });
  } catch (error) {
    console.error("ACCESS KEY ERROR:", error);

    return res.status(500).json({
      ok: false,
      code: "ACCESS_SERVER_ERROR",
      message: "The access service is temporarily unavailable."
    });
  }
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/account",
  verifyToken,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT
          id,
          email,
          role,
          status,
          created_at
        FROM users
        WHERE id = $1
        LIMIT 1
        `,
        [req.user.sub]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          ok: false,
          code: "USER_NOT_FOUND",
          message: "Account was not found."
        });
      }

      const user = result.rows[0];

      res.json({
        ok: true,
        user,
        mt5: {
          status: "NOT_CONNECTED"
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        code: "ACCOUNT_ERROR",
        message: "Unable to load account."
      });
    }
  }
);

/* =========================================================
   MT5 STATUS
========================================================= */

app.get(
  "/api/mt5/status",
  verifyToken,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT
          id,
          metaapi_account_id,
          login,
          server,
          platform,
          status
        FROM mt5_accounts
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        `,
        [req.user.sub]
      );

      if (!result.rows.length) {
        return res.json({
          ok: true,
          connected: false,
          status: "NOT_CONNECTED",
          account: null
        });
      }

      const account = result.rows[0];

      /*
        Do not claim CONNECTED merely because a database
        record exists. The real MT5 API must confirm it.
      */

      if (!account.metaapi_account_id) {
        return res.json({
          ok: true,
          connected: false,
          status: "NOT_CONNECTED",
          account: null
        });
      }

      if (!String(process.env.METAAPI_TOKEN || "").trim()) {
        return res.json({
          ok: true,
          connected: false,
          status: "NOT_CONNECTED",
          account: {
            login: account.login,
            server: account.server,
            platform: account.platform
          }
        });
      }

      try {
        const information =
          await getAccountInformation(
            account.metaapi_account_id
          );

        return res.json({
          ok: true,
          connected: true,
          status: "CONNECTED",

          account: {
            login: account.login,
            server: account.server,
            platform: account.platform,

            balance: information.balance,
            equity: information.equity,
            margin: information.margin,
            freeMargin: information.freeMargin,
            currency: information.currency
          }
        });
      } catch (error) {
        console.error(
          "REAL MT5 STATUS CHECK FAILED:",
          error.message
        );

        return res.json({
          ok: true,
          connected: false,
          status: "NOT_CONNECTED",
          account: null
        });
      }
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        code: "MT5_STATUS_ERROR",
        message: "Unable to check MT5 connection."
      });
    }
  }
);

/* =========================================================
   POSITIONS
========================================================= */

app.get(
  "/api/positions",
  verifyToken,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT metaapi_account_id
        FROM mt5_accounts
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        `,
        [req.user.sub]
      );

      if (!result.rows.length) {
        return res.json({
          ok: true,
          connected: false,
          positions: []
        });
      }

      const accountId =
        result.rows[0].metaapi_account_id;

      if (!String(process.env.METAAPI_TOKEN || "").trim()) {
        return res.json({
          ok: true,
          connected: false,
          positions: []
        });
      }

      const positions =
        await getPositions(accountId);

      return res.json({
        ok: true,
        connected: true,
        positions
      });
    } catch (error) {
      console.error("POSITIONS ERROR:", error.message);

      return res.status(503).json({
        ok: false,
        code: "MT5_NOT_CONNECTED",
        message: "MT5 is not connected.",
        positions: []
      });
    }
  }
);

/* =========================================================
   RISK GET
========================================================= */

app.get(
  "/api/risk",
  verifyToken,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT *
        FROM risk_settings
        WHERE user_id = $1
        `,
        [req.user.sub]
      );

      if (!result.rows.length) {
        await query(
          `
          INSERT INTO risk_settings (user_id)
          VALUES ($1)
          ON CONFLICT (user_id) DO NOTHING
          `,
          [req.user.sub]
        );

        const fresh = await query(
          `
          SELECT *
          FROM risk_settings
          WHERE user_id = $1
          `,
          [req.user.sub]
        );

        return res.json({
          ok: true,
          risk: fresh.rows[0]
        });
      }

      res.json({
        ok: true,
        risk: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        code: "RISK_LOAD_ERROR",
        message: "Unable to load risk settings."
      });
    }
  }
);

/* =========================================================
   RISK UPDATE
========================================================= */

app.put(
  "/api/risk",
  verifyToken,
  async (req, res) => {
    try {
      const body = req.body || {};

      const allowedBoolean = [
        "martingale_enabled",
        "recovery_enabled",
        "daily_loss_enabled",
        "stop_loss_enabled",
        "take_profit_enabled",
        "trade_size_enabled",
        "margin_check_enabled",
        "max_positions_enabled"
      ];

      const booleans = {};

      for (const field of allowedBoolean) {
        if (field in body) {
          booleans[field] = Boolean(body[field]);
        }
      }

      const riskPercent =
        Number(body.risk_percent ?? 0.5);

      const dailyLossPercent =
        Number(body.daily_loss_percent ?? 2);

      const maxPositions =
        Number(body.max_positions ?? 1);

      if (
        !Number.isFinite(riskPercent) ||
        riskPercent <= 0 ||
        riskPercent > 100
      ) {
        return res.status(400).json({
          ok: false,
          code: "INVALID_RISK",
          message: "Invalid risk percentage."
        });
      }

      if (
        !Number.isFinite(dailyLossPercent) ||
        dailyLossPercent <= 0 ||
        dailyLossPercent > 100
      ) {
        return res.status(400).json({
          ok: false,
          code: "INVALID_DAILY_LOSS",
          message: "Invalid daily loss limit."
        });
      }

      if (
        !Number.isInteger(maxPositions) ||
        maxPositions < 1 ||
        maxPositions > 100
      ) {
        return res.status(400).json({
          ok: false,
          code: "INVALID_MAX_POSITIONS",
          message: "Invalid maximum positions."
        });
      }

      await query(
        `
        INSERT INTO risk_settings (
          user_id,
          martingale_enabled,
          recovery_enabled,
          daily_loss_enabled,
          stop_loss_enabled,
          take_profit_enabled,
          trade_size_enabled,
          margin_check_enabled,
          max_positions_enabled,
          risk_percent,
          daily_loss_percent,
          max_positions,
          updated_at
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8,
          $9,
          $10,
          $11,
          $12,
          NOW()
        )
        ON CONFLICT (user_id)
        DO UPDATE SET
          martingale_enabled = EXCLUDED.martingale_enabled,
          recovery_enabled = EXCLUDED.recovery_enabled,
          daily_loss_enabled = EXCLUDED.daily_loss_enabled,
          stop_loss_enabled = EXCLUDED.stop_loss_enabled,
          take_profit_enabled = EXCLUDED.take_profit_enabled,
          trade_size_enabled = EXCLUDED.trade_size_enabled,
          margin_check_enabled = EXCLUDED.margin_check_enabled,
          max_positions_enabled = EXCLUDED.max_positions_enabled,
          risk_percent = EXCLUDED.risk_percent,
          daily_loss_percent = EXCLUDED.daily_loss_percent,
          max_positions = EXCLUDED.max_positions,
          updated_at = NOW()
        `,
        [
          req.user.sub,
          booleans.martingale_enabled ?? false,
          booleans.recovery_enabled ?? false,
          booleans.daily_loss_enabled ?? true,
          booleans.stop_loss_enabled ?? true,
          booleans.take_profit_enabled ?? true,
          booleans.trade_size_enabled ?? true,
          booleans.margin_check_enabled ?? true,
          booleans.max_positions_enabled ?? true,
          riskPercent,
          dailyLossPercent,
          maxPositions
        ]
      );

      const result = await query(
        `
        SELECT *
        FROM risk_settings
        WHERE user_id = $1
        `,
        [req.user.sub]
      );

      res.json({
        ok: true,
        risk: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        code: "RISK_UPDATE_ERROR",
        message: "Unable to save risk settings."
      });
    }
  }
);

/* =========================================================
   REAL TRADE
========================================================= */

app.post(
  "/api/trade",
  verifyToken,
  async (req, res) => {
    try {
      const tradingEnabled =
        String(
          process.env.TRADING_ENABLED || "false"
        ).toLowerCase() === "true";

      if (!tradingEnabled) {
        return res.status(403).json({
          ok: false,
          code: "TRADING_DISABLED",
          message: "Real trading is currently disabled."
        });
      }

      const {
        side,
        symbol,
        volume,
        stopLoss,
        takeProfit
      } = req.body || {};

      if (!side || !symbol || !volume) {
        return res.status(400).json({
          ok: false,
          code: "TRADE_FIELDS_REQUIRED",
          message: "Side, symbol and volume are required."
        });
      }

      const accountResult = await query(
        `
        SELECT *
        FROM mt5_accounts
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        `,
        [req.user.sub]
      );

      if (!accountResult.rows.length) {
        return res.status(409).json({
          ok: false,
          code: "MT5_NOT_CONNECTED",
          message: "Connect a real MT5 account before trading."
        });
      }

      const account =
        accountResult.rows[0];

      if (!account.metaapi_account_id) {
        return res.status(409).json({
          ok: false,
          code: "MT5_NOT_CONNECTED",
          message: "Connect a real MT5 account before trading."
        });
      }

      if (
        !String(process.env.METAAPI_TOKEN || "").trim()
      ) {
        return res.status(409).json({
          ok: false,
          code: "MT5_API_NOT_CONFIGURED",
          message: "The real MT5 cloud API is not configured."
        });
      }

      const result =
        await createMarketOrder({
          accountId: account.metaapi_account_id,
          side,
          symbol,
          volume,
          stopLoss,
          takeProfit
        });

      const tradeId =
        crypto.randomUUID();

      const brokerOrderId =
        result?.orderId ||
        result?.positionId ||
        null;

      await query(
        `
        INSERT INTO trades (
          id,
          user_id,
          account_id,
          symbol,
          side,
          volume,
          stop_loss,
          take_profit,
          mt5_order_id,
          status,
          executed_at
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8,
          $9,
          'EXECUTED',
          NOW()
        )
        `,
        [
          tradeId,
          req.user.sub,
          account.id,
          symbol,
          String(side).toUpperCase(),
          Number(volume),
          stopLoss ?? null,
          takeProfit ?? null,
          brokerOrderId
        ]
      );

      await query(
        `
        INSERT INTO audit_logs (
          id,
          user_id,
          action,
          details
        )
        VALUES (
          $1,
          $2,
          'REAL_TRADE_EXECUTED',
          $3
        )
        `,
        [
          crypto.randomUUID(),
          req.user.sub,
          JSON.stringify({
            symbol,
            side,
            volume,
            brokerOrderId
          })
        ]
      );

      res.json({
        ok: true,
        status: "EXECUTED",
        tradeId,
        brokerOrderId,
        message: "Real MT5 order executed."
      });
    } catch (error) {
      console.error("REAL TRADE ERROR:", error);

      res.status(502).json({
        ok: false,
        code: "BROKER_ORDER_FAILED",
        message:
          "The broker did not confirm the order.",
        details: error.message
      });
    }
  }
);

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
  "/api/admin/login",
  async (req, res) => {
    try {
      const email =
        String(req.body?.email || "").trim();

      const password =
        String(req.body?.password || "");

      const adminEmail =
        String(
          process.env.ADMIN_EMAIL || ""
        ).trim();

      const adminPassword =
        String(
          process.env.ADMIN_PASSWORD || ""
        );

      if (
        !adminEmail ||
        !adminPassword
      ) {
        return res.status(503).json({
          ok: false,
          code: "ADMIN_NOT_CONFIGURED",
          message: "Admin login is not configured."
        });
      }

      if (
        email !== adminEmail ||
        password !== adminPassword
      ) {
        return res.status(401).json({
          ok: false,
          code: "ADMIN_LOGIN_INVALID",
          message: "Incorrect administrator credentials."
        });
      }

      const token =
        createAdminToken();

      res.json({
        ok: true,
        token,
        role: "ADMIN"
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        code: "ADMIN_LOGIN_ERROR",
        message: "Administrator login failed."
      });
    }
  }
);

/* =========================================================
   ADMIN ME
========================================================= */

app.get(
  "/api/admin/me",
  verifyToken,
  requireAdmin,
  (req, res) => {
    res.json({
      ok: true,
      role: "ADMIN"
    });
  }
);

/* =========================================================
   ADMIN DASHBOARD
========================================================= */

app.get(
  "/api/admin/dashboard",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await query(
          `SELECT COUNT(*)::int AS count FROM users`
        );

      const accounts =
        await query(
          `SELECT COUNT(*)::int AS count FROM mt5_accounts`
        );

      const trades =
        await query(
          `SELECT COUNT(*)::int AS count FROM trades`
        );

      const bots =
        await query(
          `SELECT COUNT(*)::int AS count FROM bots`
        );

      res.json({
        ok: true,
        dashboard: {
          users: users.rows[0].count,
          mt5Accounts: accounts.rows[0].count,
          trades: trades.rows[0].count,
          bots: bots.rows[0].count
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        code: "ADMIN_DASHBOARD_ERROR",
        message: "Unable to load admin dashboard."
      });
    }
  }
);

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    code: "NOT_FOUND",
    message: "API route not found."
  });
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error);

  res.status(500).json({
    ok: false,
    code: "SERVER_ERROR",
    message: "Server error."
  });
});

/* =========================================================
   START
========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `ELISY254 CLOUD listening on port ${PORT}`
    );
  }
);
