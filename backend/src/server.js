import "dotenv/config";

import express from "express";
import cors from "cors";
import helmet from "helmet";
import crypto from "crypto";

import {
  query
} from "./db.js";

import {
  hashKey,
  createToken,
  createAdminToken,
  verifyToken,
  requireAdmin
} from "./auth.js";

import {
  validateRiskSettings
} from "./risk.js";

import {
  getAccountInformation,
  getPositions,
  createMarketOrder,
  getConnectionStatus
} from "./mt5.js";

const app = express();

const PORT =
  Number(process.env.PORT) || 4000;

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN || "*";

app.set(
  "trust proxy",
  1
);

app.use(
  helmet()
);

app.use(
  cors({
    origin:
      FRONTEND_ORIGIN === "*"
        ? true
        : FRONTEND_ORIGIN,
    credentials: true
  })
);

app.use(
  express.json({
    limit: "1mb"
  })
);

function newId() {
  return crypto.randomUUID();
}

/* =========================================================
   ROOT
========================================================= */

app.get(
  "/",
  (req, res) => {
    res.json({
      ok: true,
      name: "ELISY254 CLOUD",
      service: "backend",
      status: "online"
    });
  }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/api/health",
  async (req, res) => {
    let database =
      "offline";

    try {
      await query(
        "SELECT 1"
      );

      database =
        "online";
    } catch (error) {
      database =
        "offline";
    }

    const mt5 =
      getConnectionStatus();

    const tradingEnabled =
      process.env.TRADING_ENABLED ===
      "true";

    res.json({
      ok:
        database ===
        "online",

      service:
        "ELISY254 CLOUD",

      backend: {
        status:
          "online"
      },

      database,

      mt5: {
        provider:
          mt5.provider,

        metaApiConfigured:
          mt5.metaApiConfigured,

        terminalConfigured:
          mt5.terminalConfigured,

        status:
          "NOT_CONNECTED"
      },

      trading: {
        enabled:
          tradingEnabled,

        status:
          tradingEnabled
            ? "ENABLED"
            : "DISABLED"
      }
    });
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
        String(
          req.body?.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body?.password || ""
        );

      if (
        !email ||
        !password
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            message:
              "Email and password are required"
          });
      }

      const configuredEmail =
        String(
          process.env.ADMIN_EMAIL || ""
        )
          .trim()
          .toLowerCase();

      const configuredPassword =
        String(
          process.env.ADMIN_PASSWORD || ""
        );

      if (
        !configuredEmail ||
        !configuredPassword
      ) {
        return res
          .status(503)
          .json({
            ok: false,
            message:
              "Admin credentials are not configured on the server"
          });
      }

      if (
        email !==
          configuredEmail ||
        password !==
          configuredPassword
      ) {
        return res
          .status(401)
          .json({
            ok: false,
            message:
              "Invalid admin credentials"
          });
      }

      const token =
        createAdminToken();

      return res.json({
        ok: true,
        token,
        role:
          "ADMIN"
      });

    } catch (error) {
      console.error(
        "ADMIN LOGIN ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,
          message:
            "Admin login failed"
        });
    }
  }
);

/* =========================================================
   ADMIN CHECK
========================================================= */

app.get(
  "/api/admin/me",
  verifyToken,
  requireAdmin,
  (req, res) => {
    res.json({
      ok: true,
      role:
        "ADMIN"
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
          `
          SELECT COUNT(*)::int AS count
          FROM users
          `
        );

      const accounts =
        await query(
          `
          SELECT COUNT(*)::int AS count
          FROM mt5_accounts
          `
        );

      const bots =
        await query(
          `
          SELECT COUNT(*)::int AS count
          FROM bots
          WHERE status = 'PUBLISHED'
          `
        );

      const trades =
        await query(
          `
          SELECT COUNT(*)::int AS count
          FROM trades
          `
        );

      res.json({
        ok: true,

        dashboard: {
          users:
            users.rows[0].count,

          mt5Accounts:
            accounts.rows[0].count,

          publishedBots:
            bots.rows[0].count,

          trades:
            trades.rows[0].count
        }
      });

    } catch (error) {
      console.error(
        "ADMIN DASHBOARD ERROR:",
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            "Unable to load admin dashboard"
        });
    }
  }
);

/* =========================================================
   USER ACCESS KEY
========================================================= */

app.post(
  "/api/auth/key",
  async (req, res) => {
    try {
      const key =
        String(
          req.body?.key || ""
        ).trim();

      if (!key) {
        return res
          .status(400)
          .json({
            ok: false,
            message:
              "Access key is required"
          });
      }

      const configuredKey =
        String(
          process.env.ELISY_ACCESS_KEY ||
          ""
        );

      if (
        !configuredKey ||
        key !== configuredKey
      ) {
        return res
          .status(401)
          .json({
            ok: false,
            message:
              "Invalid access key"
          });
      }

      const keyHash =
        hashKey(key);

      let result =
        await query(
          `
          SELECT
            id,
            role,
            status
          FROM users
          WHERE access_key_hash = $1
          LIMIT 1
          `,
          [keyHash]
        );

      let user;

      if (
        result.rows.length
      ) {
        user =
          result.rows[0];
      } else {
        result =
          await query(
            `
            INSERT INTO users
            (
              id,
              email,
              access_key_hash,
              role,
              status
            )
            VALUES
            (
              $1,
              NULL,
              $2,
              'USER',
              'ACTIVE'
            )
            RETURNING
              id,
              role,
              status
            `,
            [
              newId(),
              keyHash
            ]
          );

        user =
          result.rows[0];

        await query(
          `
          INSERT INTO risk_settings
          (
            user_id
          )
          VALUES
          ($1)
          ON CONFLICT
          (user_id)
          DO NOTHING
          `,
          [user.id]
        );
      }

      if (
        user.status !==
        "ACTIVE"
      ) {
        return res
          .status(403)
          .json({
            ok: false,
            message:
              "User account is disabled"
          });
      }

      const token =
        createToken(user);

      return res.json({
        ok: true,

        token,

        user: {
          id:
            user.id,

          role:
            user.role
        }
      });

    } catch (error) {
      console.error(
        "AUTH KEY ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,
          message:
            "Unable to verify access key"
        });
    }
  }
);

/* =========================================================
   ACCOUNT
========================================================= */

app.get(
  "/api/account",
  verifyToken,
  async (req, res) => {
    try {
      const result =
        await query(
          `
          SELECT *
          FROM mt5_accounts
          WHERE user_id = $1
          ORDER BY created_at DESC
          LIMIT 1
          `,
          [req.user.sub]
        );

      if (
        !result.rows.length
      ) {
        return res.json({
          ok: true,
          connected:
            false,
          status:
            "NOT_CONNECTED",
          account:
            null
        });
      }

      const account =
        result.rows[0];

      try {
        const info =
          await getAccountInformation(
            account.metaapi_account_id
          );

        return res.json({
          ok: true,

          connected:
            true,

          status:
            "CONNECTED",

          account: {
            id:
              account.id,

            login:
              account.login,

            server:
              account.server,

            platform:
              account.platform,

            balance:
              info.balance,

            equity:
              info.equity,

            freeMargin:
              info.freeMargin,

            margin:
              info.margin,

            marginLevel:
              info.marginLevel,

            currency:
              info.currency
          }
        });

      } catch (error) {
        console.error(
          "MT5 ACCOUNT NOT CONNECTED:",
          error.message
        );

        return res.json({
          ok: true,

          connected:
            false,

          status:
            "NOT_CONNECTED",

          account: {
            id:
              account.id,

            login:
              account.login,

            server:
              account.server,

            platform:
              account.platform
          }
        });
      }

    } catch (error) {
      console.error(
        "ACCOUNT ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,
          message:
            "Unable to load account"
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
      const result =
        await query(
          `
          SELECT *
          FROM mt5_accounts
          WHERE user_id = $1
          ORDER BY created_at DESC
          LIMIT 1
          `,
          [req.user.sub]
        );

      if (
        !result.rows.length
      ) {
        return res.json({
          ok: true,
          connected:
            false,
          positions: []
        });
      }

      const positions =
        await getPositions(
          result.rows[0]
            .metaapi_account_id
        );

      return res.json({
        ok: true,
        connected:
          true,
        positions
      });

    } catch (error) {
      return res.json({
        ok: true,
        connected:
          false,
        positions: []
      });
    }
  }
);

/* =========================================================
   RISK SETTINGS
========================================================= */

app.get(
  "/api/risk",
  verifyToken,
  async (req, res) => {
    try {
      const result =
        await query(
          `
          SELECT *
          FROM risk_settings
          WHERE user_id = $1
          `,
          [req.user.sub]
        );

      if (
        !result.rows.length
      ) {
        return res
          .status(404)
          .json({
            ok: false,
            message:
              "Risk settings not found"
          });
      }

      return res.json({
        ok: true,
        settings:
          result.rows[0]
      });

    } catch (error) {
      console.error(
        "RISK GET ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,
          message:
            "Unable to load risk settings"
        });
    }
  }
);

app.put(
  "/api/risk",
  verifyToken,
  async (req, res) => {
    try {
      const settings =
        req.body || {};

      validateRiskSettings(
        settings
      );

      const result =
        await query(
          `
          UPDATE risk_settings
          SET
            martingale_enabled = $1,
            recovery_enabled = $2,
            daily_loss_enabled = $3,
            stop_loss_enabled = $4,
            take_profit_enabled = $5,
            trade_size_enabled = $6,
            margin_check_enabled = $7,
            max_positions_enabled = $8,
            risk_percent = $9,
            daily_loss_percent = $10,
            max_positions = $11,
            updated_at = NOW()
          WHERE user_id = $12
          RETURNING *
          `,
          [
            Boolean(
              settings.martingale_enabled
            ),

            Boolean(
              settings.recovery_enabled
            ),

            Boolean(
              settings.daily_loss_enabled
            ),

            Boolean(
              settings.stop_loss_enabled
            ),

            Boolean(
              settings.take_profit_enabled
            ),

            Boolean(
              settings.trade_size_enabled
            ),

            Boolean(
              settings.margin_check_enabled
            ),

            Boolean(
              settings.max_positions_enabled
            ),

            Number(
              settings.risk_percent
            ),

            Number(
              settings.daily_loss_percent
            ),

            Number(
              settings.max_positions
            ),

            req.user.sub
          ]
        );

      return res.json({
        ok: true,
        settings:
          result.rows[0]
      });

    } catch (error) {
      return res
        .status(400)
        .json({
          ok: false,
          message:
            error.message
        });
    }
  }
);

/* =========================================================
   TRADE
========================================================= */

app.post(
  "/api/trade",
  verifyToken,
  async (req, res) => {
    try {
      if (
        process.env.TRADING_ENABLED !==
        "true"
      ) {
        return res
          .status(403)
          .json({
            ok: false,
            executed:
              false,
            message:
              "Live trading is disabled"
          });
      }

      const {
        symbol,
        side,
        volume,
        stopLoss,
        takeProfit
      } =
        req.body || {};

      if (
        !symbol ||
        !side
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            executed:
              false,
            message:
              "Symbol and side are required"
          });
      }

      const accountResult =
        await query(
          `
          SELECT *
          FROM mt5_accounts
          WHERE user_id = $1
          ORDER BY created_at DESC
          LIMIT 1
          `,
          [req.user.sub]
        );

      if (
        !accountResult.rows.length
      ) {
        return res
          .status(409)
          .json({
            ok: false,
            executed:
              false,
            message:
              "MT5 account is not connected"
          });
      }

      const account =
        accountResult.rows[0];

      const result =
        await createMarketOrder({
          accountId:
            account.metaapi_account_id,

          side,

          symbol,

          volume,

          stopLoss,

          takeProfit
        });

      await query(
        `
        INSERT INTO trades
        (
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
        VALUES
        (
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
          NOW()
        )
        `,
        [
          newId(),

          req.user.sub,

          account.id,

          symbol,

          String(
            side
          ).toUpperCase(),

          Number(
            volume
          ),

          stopLoss ||
            null,

          takeProfit ||
            null,

          result?.orderId ||
            result?.positionId ||
            null,

          "EXECUTED"
        ]
      );

      return res.json({
        ok: true,
        executed:
          true,
        result
      });

    } catch (error) {
      console.error(
        "TRADE ERROR:",
        error
      );

      return res
        .status(400)
        .json({
          ok: false,
          executed:
            false,
          message:
            error.message
        });
    }
  }
);

/* =========================================================
   SERVER START
========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      "======================================"
    );

    console.log(
      "ELISY254 CLOUD BACKEND"
    );

    console.log(
      `PORT: ${PORT}`
    );

    console.log(
      `MT5 PROVIDER: ${
        process.env.MT5_PROVIDER ||
        "AUTO"
      }`
    );

    console.log(
      `METAAPI CONFIGURED: ${
        Boolean(
          process.env.METAAPI_TOKEN
        )
      }`
    );

    console.log(
      `TERMINAL CONFIGURED: ${
        Boolean(
          process.env.TERMINAL_BRIDGE_URL
        )
      }`
    );

    console.log(
      `TRADING ENABLED: ${
        process.env.TRADING_ENABLED ===
        "true"
      }`
    );

    console.log(
      "======================================"
    );
  }
);
