import "dotenv/config";

import express from "express";
import cors from "cors";
import helmet from "helmet";
import crypto from "crypto";
import bcrypt from "bcryptjs";

import { query } from "./db.js";
import { hashKey, createToken, verifyToken } from "./auth.js";
import {
  validateRiskSettings,
  calculateRiskMoney,
  checkDailyLoss
} from "./risk.js";

import {
  getAccountInformation,
  getPositions,
  createMarketOrder
} from "./mt5.js";

const app = express();

const PORT = Number(
  process.env.PORT || 4000
);

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN || "*";

app.use(helmet());

app.use(
  cors({
    origin:
      FRONTEND_ORIGIN === "*"
        ? true
        : FRONTEND_ORIGIN,
    credentials: true
  })
);

app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    name: "ELISY254 CLOUD",
    status: "online",
    liveTrading:
      process.env.TRADING_ENABLED === "true"
  });
});

app.get("/api/health", async (req, res) => {
  try {
    await query("SELECT 1");

    res.json({
      ok: true,
      database: "connected",
      mt5ApiConfigured:
        Boolean(process.env.METAAPI_TOKEN),
      liveTrading:
        process.env.TRADING_ENABLED === "true"
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      database: "error",
      message: error.message
    });
  }
});

/*
  ACCESS KEY
*/

app.post("/api/auth/key", async (req, res) => {
  try {
    const { key } = req.body || {};

    if (!key) {
      return res.status(401).json({
        ok: false,
        message: "Access key required"
      });
    }

    const expected =
      process.env.ELISY_ACCESS_KEY;

    if (!expected) {
      return res.status(503).json({
        ok: false,
        message: "Access service is not configured"
      });
    }

    const receivedHash =
      hashKey(key);

    const expectedHash =
      hashKey(expected);

    const valid =
      crypto.timingSafeEqual(
        Buffer.from(receivedHash),
        Buffer.from(expectedHash)
      );

    if (!valid) {
      return res.status(401).json({
        ok: false,
        message: "Invalid access key"
      });
    }

    const userId =
      crypto.randomUUID();

    const email =
      `key-${userId}@elisy254.local`;

    const passwordHash =
      await bcrypt.hash(
        crypto.randomUUID(),
        12
      );

    await query(
      `
      INSERT INTO users
      (id, email, access_key_hash)
      VALUES ($1, $2, $3)
      ON CONFLICT (email) DO NOTHING
      `,
      [
        userId,
        email,
        passwordHash
      ]
    );

    await query(
      `
      INSERT INTO risk_settings (user_id)
      VALUES ($1)
      ON CONFLICT (user_id) DO NOTHING
      `,
      [userId]
    );

    const token =
      createToken({
        id: userId,
        role: "USER"
      });

    res.json({
      ok: true,
      userId,
      token
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      ok: false,
      message: "Authentication failed"
    });
  }
});

/*
  ACCOUNT INFORMATION
*/

app.get(
  "/api/account",
  verifyToken,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT *
        FROM mt5_accounts
        WHERE user_id = $1
        LIMIT 1
        `,
        [req.user.sub]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          ok: false,
          message: "No MT5 account connected"
        });
      }

      const account =
        result.rows[0];

      const information =
        await getAccountInformation(
          account.metaapi_account_id
        );

      res.json({
        ok: true,
        account: information
      });
    } catch (error) {
      res.status(502).json({
        ok: false,
        message:
          "MT5 account information unavailable",
        error: error.message
      });
    }
  }
);

/*
  POSITIONS
*/

app.get(
  "/api/positions",
  verifyToken,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT *
        FROM mt5_accounts
        WHERE user_id = $1
        LIMIT 1
        `,
        [req.user.sub]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          ok: false,
          message: "No MT5 account connected"
        });
      }

      const positions =
        await getPositions(
          result.rows[0]
            .metaapi_account_id
        );

      res.json({
        ok: true,
        positions
      });
    } catch (error) {
      res.status(502).json({
        ok: false,
        message: "Unable to read MT5 positions",
        error: error.message
      });
    }
  }
);

/*
  RISK SETTINGS
*/

app.get(
  "/api/risk",
  verifyToken,
  async (req, res) => {
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
      settings: result.rows[0]
    });
  }
);

app.put(
  "/api/risk",
  verifyToken,
  async (req, res) => {
    try {
      const settings = {
        ...req.body
      };

      validateRiskSettings(settings);

      const result = await query(
        `
        UPDATE risk_settings
        SET
          martingale_enabled = $2,
          recovery_enabled = $3,
          daily_loss_enabled = $4,
          stop_loss_enabled = $5,
          take_profit_enabled = $6,
          trade_size_enabled = $7,
          margin_check_enabled = $8,
          max_positions_enabled = $9,
          risk_percent = $10,
          daily_loss_percent = $11,
          max_positions = $12,
          updated_at = NOW()
        WHERE user_id = $1
        RETURNING *
        `,
        [
          req.user.sub,
          Boolean(settings.martingale_enabled),
          Boolean(settings.recovery_enabled),
          Boolean(settings.daily_loss_enabled),
          Boolean(settings.stop_loss_enabled),
          Boolean(settings.take_profit_enabled),
          Boolean(settings.trade_size_enabled),
          Boolean(settings.margin_check_enabled),
          Boolean(settings.max_positions_enabled),
          Number(settings.risk_percent),
          Number(settings.daily_loss_percent),
          Number(settings.max_positions)
        ]
      );

      res.json({
        ok: true,
        settings: result.rows[0]
      });
    } catch (error) {
      res.status(400).json({
        ok: false,
        message: error.message
      });
    }
  }
);

/*
  LIVE ORDER
*/

app.post(
  "/api/trade",
  verifyToken,
  async (req, res) => {
    try {
      if (
        process.env.TRADING_ENABLED !== "true"
      ) {
        return res.status(403).json({
          ok: false,
          message:
            "Live trading is disabled on this server"
        });
      }

      const {
        symbol,
        side,
        volume,
        stopLoss,
        takeProfit
      } = req.body || {};

      if (!symbol || !side || !volume) {
        return res.status(400).json({
          ok: false,
          message:
            "symbol, side and volume are required"
        });
      }

      const accountResult =
        await query(
          `
          SELECT *
          FROM mt5_accounts
          WHERE user_id = $1
          LIMIT 1
          `,
          [req.user.sub]
        );

      if (!accountResult.rows.length) {
        return res.status(409).json({
          ok: false,
          message:
            "MT5 account is not connected"
        });
      }

      const account =
        accountResult.rows[0];

      const riskResult =
        await query(
          `
          SELECT *
          FROM risk_settings
          WHERE user_id = $1
          `,
          [req.user.sub]
        );

      const risk =
        riskResult.rows[0];

      validateRiskSettings(risk);

      const information =
        await getAccountInformation(
          account.metaapi_account_id
        );

      if (!information.tradeAllowed) {
        return res.status(403).json({
          ok: false,
          message:
            "Broker does not currently allow trading"
        });
      }

      if (
        risk.max_positions_enabled
      ) {
        const positions =
          await getPositions(
            account.metaapi_account_id
          );

        if (
          positions.length >=
          risk.max_positions
        ) {
          return res.status(403).json({
            ok: false,
            message:
              "Maximum open positions reached"
          });
        }
      }

      if (
        risk.daily_loss_enabled
      ) {
        const daily =
          checkDailyLoss(
            information.balance,
            information.equity,
            risk.daily_loss_percent
          );

        if (!daily.allowed) {
          return res.status(403).json({
            ok: false,
            message:
              "Daily loss limit reached"
          });
        }
      }

      if (
        risk.margin_check_enabled &&
        Number(information.freeMargin) <= 0
      ) {
        return res.status(403).json({
          ok: false,
          message:
            "Insufficient free margin"
        });
      }

      if (
        risk.stop_loss_enabled &&
        !stopLoss
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Stop loss is required by risk settings"
        });
      }

      const trade =
        await createMarketOrder({
          accountId:
            account.metaapi_account_id,
          side,
          symbol,
          volume,
          stopLoss,
          takeProfit
        });

      const tradeId =
        crypto.randomUUID();

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
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW()
        )
        `,
        [
          tradeId,
          req.user.sub,
          account.id,
          symbol,
          side,
          volume,
          stopLoss || null,
          takeProfit || null,
          trade.orderId || null,
          "EXECUTED"
        ]
      );

      await query(
        `
        INSERT INTO audit_logs
        (id, user_id, action, details)
        VALUES ($1,$2,$3,$4)
        `,
        [
          crypto.randomUUID(),
          req.user.sub,
          "LIVE_TRADE_EXECUTED",
          JSON.stringify({
            tradeId,
            symbol,
            side,
            volume,
            orderId:
              trade.orderId || null
          })
        ]
      );

      res.json({
        ok: true,
        trade
      });
    } catch (error) {
      console.error(error);

      res.status(502).json({
        ok: false,
        message:
          "Live MT5 order failed",
        error: error.message
      });
    }
  }
);

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `ELISY254 CLOUD running on ${PORT}`
    );
  }
);
