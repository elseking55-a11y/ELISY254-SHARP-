'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 10000);

const NODE_ENV = process.env.NODE_ENV || 'development';

const DATABASE_URL = process.env.DATABASE_URL;

const ACCESS_KEY = process.env.ACCESS_KEY || '';
const JWT_SECRET = process.env.JWT_SECRET || '';

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || '';

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  'https://frontend-six-jade-97.vercel.app';

const TRADING_ENABLED =
  String(process.env.TRADING_ENABLED || 'false').toLowerCase() === 'true';

const MT5_PROVIDER =
  String(process.env.MT5_PROVIDER || 'metaapi').toLowerCase();

const METAAPI_TOKEN = process.env.METAAPI_TOKEN || '';

const METAAPI_REGION =
  process.env.METAAPI_REGION || 'new-york';

const TERMINAL_BRIDGE_URL =
  process.env.TERMINAL_BRIDGE_URL || '';

/* =========================================================
   BASIC VALIDATION
========================================================= */

if (!DATABASE_URL) {
  console.warn('WARNING: DATABASE_URL is not configured.');
}

if (!ACCESS_KEY) {
  console.warn('WARNING: ACCESS_KEY is not configured.');
}

if (!JWT_SECRET) {
  console.warn('WARNING: JWT_SECRET is not configured.');
}

if (!ADMIN_JWT_SECRET) {
  console.warn('WARNING: ADMIN_JWT_SECRET is not configured.');
}

/* =========================================================
   CORS
========================================================= */

const allowedOrigins = new Set([
  FRONTEND_URL,
  'http://localhost:5173',
  'http://localhost:3000'
]);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.has(origin)) {
        return callback(null, true);
      }

      return callback(new Error('CORS origin not allowed'));
    },
    credentials: true
  })
);

/* =========================================================
   BODY PARSER
========================================================= */

app.use(
  express.json({
    limit: '1mb'
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '1mb'
  })
);

/* =========================================================
   DATABASE
========================================================= */

let pool = null;

if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl:
      NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
  });
}

async function dbQuery(text, params = []) {
  if (!pool) {
    throw new Error('DATABASE_URL is not configured');
  }

  return pool.query(text, params);
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initializeDatabase() {
  if (!pool) {
    return;
  }

  await dbQuery(`
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      access_key_hash TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_activity TIMESTAMPTZ
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS mt5_accounts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

      user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      provider TEXT NOT NULL DEFAULT 'metaapi',

      provider_account_id TEXT UNIQUE,

      name TEXT NOT NULL,
      broker TEXT,
      server TEXT,
      platform TEXT NOT NULL DEFAULT 'mt5',

      connection_status TEXT NOT NULL DEFAULT 'UNKNOWN',
      state TEXT,

      login_masked TEXT,

      balance NUMERIC,
      equity NUMERIC,
      free_margin NUMERIC,
      currency TEXT,

      last_sync TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS bots (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

      name TEXT NOT NULL,
      description TEXT,

      version TEXT NOT NULL DEFAULT '1.0.0',

      status TEXT NOT NULL DEFAULT 'DRAFT',

      image_url TEXT,
      file_url TEXT,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS trades (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

      user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      mt5_account_id UUID
        REFERENCES mt5_accounts(id)
        ON DELETE SET NULL,

      action_type TEXT,
      symbol TEXT,
      volume NUMERIC,

      order_id TEXT,

      broker_code TEXT,
      broker_message TEXT,

      status TEXT NOT NULL,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

      user_id UUID
        REFERENCES users(id)
        ON DELETE SET NULL,

      event TEXT NOT NULL,

      details JSONB,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log('Database initialized.');
}

/* =========================================================
   HELPERS
========================================================= */

function hashAccessKey(value) {
  return crypto
    .createHash('sha256')
    .update(String(value))
    .digest('hex');
}

function maskLogin(login) {
  const value = String(login);

  if (value.length <= 3) {
    return '***';
  }

  return `${value.slice(0, 2)}***${value.slice(-2)}`;
}

function signUserToken(user) {
  return jwt.sign(
    {
      type: 'user',
      sub: user.id
    },
    JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );
}

function signAdminToken() {
  return jwt.sign(
    {
      type: 'admin',
      email: ADMIN_EMAIL
    },
    ADMIN_JWT_SECRET,
    {
      expiresIn: '12h'
    }
  );
}

function safeNumber(value) {
  if (value === null || value === undefined) {
    return null;
  }

  const number = Number(value);

  return Number.isFinite(number) ? number : null;
}

async function audit(userId, event, details = {}) {
  try {
    await dbQuery(
      `
      INSERT INTO audit_logs
      (user_id, event, details)
      VALUES ($1, $2, $3)
      `,
      [
        userId || null,
        event,
        JSON.stringify(details)
      ]
    );
  } catch (error) {
    console.error('Audit log error:', error.message);
  }
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function requireUser(req, res, next) {
  try {
    const header = req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({
        ok: false,
        error: 'Authentication required'
      });
    }

    const token = header.substring(7);

    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.type !== 'user') {
      return res.status(401).json({
        ok: false,
        error: 'Invalid user token'
      });
    }

    req.userId = decoded.sub;

    next();
  } catch (error) {
    return res.status(401).json({
      ok: false,
      error: 'Invalid or expired authentication token'
    });
  }
}

function requireAdmin(req, res, next) {
  try {
    const header = req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({
        ok: false,
        error: 'Admin authentication required'
      });
    }

    const token = header.substring(7);

    const decoded = jwt.verify(
      token,
      ADMIN_JWT_SECRET
    );

    if (decoded.type !== 'admin') {
      return res.status(401).json({
        ok: false,
        error: 'Invalid admin token'
      });
    }

    req.adminEmail = decoded.email;

    next();
  } catch (error) {
    return res.status(401).json({
      ok: false,
      error: 'Invalid or expired admin token'
    });
  }
}

/* =========================================================
   METAAPI ADAPTER
========================================================= */

const METAAPI_CLIENT_BASE =
  `https://mt-client-api-v1.${METAAPI_REGION}.agiliumtrade.ai`;

const METAAPI_PROVISIONING_BASE =
  'https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai';

function metaApiHeaders() {
  return {
    'Content-Type': 'application/json',
    'auth-token': METAAPI_TOKEN
  };
}

async function metaApiRequest(
  baseUrl,
  path,
  options = {}
) {
  if (!METAAPI_TOKEN) {
    throw new Error(
      'METAAPI_TOKEN is not configured'
    );
  }

  const response = await fetch(
    `${baseUrl}${path}`,
    {
      method: options.method || 'GET',
      headers: {
        ...metaApiHeaders(),
        ...(options.headers || {})
      },
      body:
        options.body === undefined
          ? undefined
          : JSON.stringify(options.body)
    }
  );

  const text = await response.text();

  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    const error = new Error(
      data?.message ||
      data?.error ||
      `MetaApi request failed: ${response.status}`
    );

    error.status = response.status;
    error.providerResponse = data;

    throw error;
  }

  return data;
}

async function metaApiCreateAccount({
  login,
  password,
  name,
  server
}) {
  return metaApiRequest(
    METAAPI_PROVISIONING_BASE,
    '/users/current/accounts',
    {
      method: 'POST',
      body: {
        login: String(login),
        password: String(password),
        name: String(name),
        server: String(server),
        platform: 'mt5',
        type: 'cloud-g2'
      }
    }
  );
}

async function metaApiGetAccount(accountId) {
  return metaApiRequest(
    METAAPI_PROVISIONING_BASE,
    `/users/current/accounts/${encodeURIComponent(accountId)}`
  );
}

async function metaApiDeployAccount(accountId) {
  return metaApiRequest(
    METAAPI_PROVISIONING_BASE,
    `/users/current/accounts/${encodeURIComponent(accountId)}/deploy`,
    {
      method: 'POST',
      body: {}
    }
  );
}

async function metaApiUndeployAccount(accountId) {
  return metaApiRequest(
    METAAPI_PROVISIONING_BASE,
    `/users/current/accounts/${encodeURIComponent(accountId)}/undeploy`,
    {
      method: 'POST',
      body: {}
    }
  );
}

async function metaApiAccountInformation(accountId) {
  return metaApiRequest(
    METAAPI_CLIENT_BASE,
    `/users/current/accounts/${encodeURIComponent(accountId)}/account-information`
  );
}

async function metaApiPositions(accountId) {
  return metaApiRequest(
    METAAPI_CLIENT_BASE,
    `/users/current/accounts/${encodeURIComponent(accountId)}/positions`
  );
}

async function metaApiCalculateMargin(
  accountId,
  payload
) {
  return metaApiRequest(
    METAAPI_CLIENT_BASE,
    `/users/current/accounts/${encodeURIComponent(accountId)}/calculate-margin`,
    {
      method: 'POST',
      body: payload
    }
  );
}

async function metaApiTrade(
  accountId,
  payload
) {
  return metaApiRequest(
    METAAPI_CLIENT_BASE,
    `/users/current/accounts/${encodeURIComponent(accountId)}/trade`,
    {
      method: 'POST',
      body: payload
    }
  );
}

/* =========================================================
   TERMINAL ADAPTER
========================================================= */

async function terminalRequest(path, options = {}) {
  if (!TERMINAL_BRIDGE_URL) {
    throw new Error(
      'TERMINAL_BRIDGE_URL is not configured'
    );
  }

  const response = await fetch(
    `${TERMINAL_BRIDGE_URL}${path}`,
    {
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json'
      },
      body:
        options.body === undefined
          ? undefined
          : JSON.stringify(options.body)
    }
  );

  const text = await response.text();

  let data;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    throw new Error(
      data?.error ||
      `Terminal bridge error: ${response.status}`
    );
  }

  return data;
}

/* =========================================================
   MT5 PROVIDER ROUTING
========================================================= */

function providerConfigured() {
  if (MT5_PROVIDER === 'metaapi') {
    return Boolean(METAAPI_TOKEN);
  }

  if (MT5_PROVIDER === 'terminal') {
    return Boolean(TERMINAL_BRIDGE_URL);
  }

  return false;
}

async function providerCreateAccount(data) {
  if (MT5_PROVIDER === 'metaapi') {
    return metaApiCreateAccount(data);
  }

  if (MT5_PROVIDER === 'terminal') {
    return terminalRequest(
      '/api/accounts',
      {
        method: 'POST',
        body: data
      }
    );
  }

  throw new Error(
    `Unsupported MT5_PROVIDER: ${MT5_PROVIDER}`
  );
}

async function providerGetAccount(accountId) {
  if (MT5_PROVIDER === 'metaapi') {
    return metaApiGetAccount(accountId);
  }

  if (MT5_PROVIDER === 'terminal') {
    return terminalRequest(
      `/api/accounts/${encodeURIComponent(accountId)}`
    );
  }

  throw new Error('Unsupported MT5 provider');
}

async function providerDeployAccount(accountId) {
  if (MT5_PROVIDER === 'metaapi') {
    return metaApiDeployAccount(accountId);
  }

  if (MT5_PROVIDER === 'terminal') {
    return terminalRequest(
      `/api/accounts/${encodeURIComponent(accountId)}/connect`,
      {
        method: 'POST',
        body: {}
      }
    );
  }

  throw new Error('Unsupported MT5 provider');
}

async function providerAccountInformation(accountId) {
  if (MT5_PROVIDER === 'metaapi') {
    return metaApiAccountInformation(accountId);
  }

  if (MT5_PROVIDER === 'terminal') {
    return terminalRequest(
      `/api/accounts/${encodeURIComponent(accountId)}/account-information`
    );
  }

  throw new Error('Unsupported MT5 provider');
}

async function providerPositions(accountId) {
  if (MT5_PROVIDER === 'metaapi') {
    return metaApiPositions(accountId);
  }

  if (MT5_PROVIDER === 'terminal') {
    return terminalRequest(
      `/api/accounts/${encodeURIComponent(accountId)}/positions`
    );
  }

  throw new Error('Unsupported MT5 provider');
}

async function providerCalculateMargin(
  accountId,
  payload
) {
  if (MT5_PROVIDER === 'metaapi') {
    return metaApiCalculateMargin(
      accountId,
      payload
    );
  }

  if (MT5_PROVIDER === 'terminal') {
    return terminalRequest(
      `/api/accounts/${encodeURIComponent(accountId)}/calculate-margin`,
      {
        method: 'POST',
        body: payload
      }
    );
  }

  throw new Error('Unsupported MT5 provider');
}

async function providerTrade(
  accountId,
  payload
) {
  if (MT5_PROVIDER === 'metaapi') {
    return metaApiTrade(
      accountId,
      payload
    );
  }

  if (MT5_PROVIDER === 'terminal') {
    return terminalRequest(
      `/api/accounts/${encodeURIComponent(accountId)}/trade`,
      {
        method: 'POST',
        body: payload
      }
    );
  }

  throw new Error('Unsupported MT5 provider');
}

/* =========================================================
   ROOT
========================================================= */

app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'ELISY254 CLOUD',
    message: 'Backend is running',
    environment: NODE_ENV
  });
});

/* =========================================================
   HEALTH
========================================================= */

app.get('/api/health', async (req, res) => {
  let database = 'NOT_CONFIGURED';

  if (pool) {
    try {
      await dbQuery('SELECT 1');
      database = 'CONNECTED';
    } catch {
      database = 'ERROR';
    }
  }

  res.json({
    ok: true,
    service: 'ELISY254 CLOUD',
    database,
    mt5Provider: MT5_PROVIDER,
    mt5ProviderConfigured: providerConfigured(),
    tradingEnabled: TRADING_ENABLED,
    timestamp: new Date().toISOString()
  });
});

/* =========================================================
   STATUS
========================================================= */

app.get('/api/status', async (req, res) => {
  let databaseConnected = false;

  if (pool) {
    try {
      await dbQuery('SELECT 1');
      databaseConnected = true;
    } catch {
      databaseConnected = false;
    }
  }

  res.json({
    ok: true,

    cloud: {
      status: 'ONLINE'
    },

    database: {
      status: databaseConnected
        ? 'CONNECTED'
        : 'DISCONNECTED'
    },

    mt5: {
      provider: MT5_PROVIDER,
      configured: providerConfigured(),
      status: 'NOT_VERIFIED'
    },

    trading: {
      enabled: TRADING_ENABLED
    },

    timestamp: new Date().toISOString()
  });
});

/* =========================================================
   USER ACCESS KEY LOGIN
========================================================= */

app.post('/api/auth/key', async (req, res) => {
  try {
    const key = String(
      req.body?.accessKey || ''
    ).trim();

    if (!key) {
      return res.status(400).json({
        ok: false,
        error: 'Access key is required'
      });
    }

    if (!ACCESS_KEY) {
      return res.status(503).json({
        ok: false,
        error: 'Access system is not configured'
      });
    }

    if (key !== ACCESS_KEY) {
      return res.status(401).json({
        ok: false,
        error: 'Invalid access key'
      });
    }

    const keyHash = hashAccessKey(key);

    let result = await dbQuery(
      `
      SELECT *
      FROM users
      WHERE access_key_hash = $1
      LIMIT 1
      `,
      [keyHash]
    );

    let user;

    if (result.rows.length === 0) {
      result = await dbQuery(
        `
        INSERT INTO users
        (access_key_hash, status, last_activity)
        VALUES ($1, 'ACTIVE', NOW())
        RETURNING *
        `,
        [keyHash]
      );

      user = result.rows[0];
    } else {
      user = result.rows[0];

      if (user.status !== 'ACTIVE') {
        return res.status(403).json({
          ok: false,
          error: 'User account is disabled'
        });
      }

      await dbQuery(
        `
        UPDATE users
        SET last_activity = NOW()
        WHERE id = $1
        `,
        [user.id]
      );
    }

    const token = signUserToken(user);

    await audit(
      user.id,
      'USER_LOGIN',
      {}
    );

    res.json({
      ok: true,
      token,
      user: {
        id: user.id,
        status: user.status
      }
    });
  } catch (error) {
    console.error('Auth error:', error.message);

    res.status(500).json({
      ok: false,
      error: 'Authentication failed'
    });
  }
});

/* =========================================================
   USER ME
========================================================= */

app.get(
  '/api/auth/me',
  requireUser,
  async (req, res) => {
    try {
      const result = await dbQuery(
        `
        SELECT
          id,
          status,
          created_at,
          last_activity
        FROM users
        WHERE id = $1
        LIMIT 1
        `,
        [req.userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          ok: false,
          error: 'User not found'
        });
      }

      res.json({
        ok: true,
        user: result.rows[0]
      });
    } catch (error) {
      res.status(500).json({
        ok: false,
        error: 'Unable to load user'
      });
    }
  }
);

/* =========================================================
   USER MT5 ACCOUNTS
========================================================= */

app.get(
  '/api/mt5/accounts',
  requireUser,
  async (req, res) => {
    try {
      const result = await dbQuery(
        `
        SELECT
          id,
          provider,
          provider_account_id,
          name,
          broker,
          server,
          platform,
          connection_status,
          state,
          login_masked,
          balance,
          equity,
          free_margin,
          currency,
          last_sync,
          created_at
        FROM mt5_accounts
        WHERE user_id = $1
        ORDER BY created_at DESC
        `,
        [req.userId]
      );

      res.json({
        ok: true,
        accounts: result.rows
      });
    } catch (error) {
      console.error(
        'MT5 accounts error:',
        error.message
      );

      res.status(500).json({
        ok: false,
        error: 'Unable to load MT5 accounts'
      });
    }
  }
);

/* =========================================================
   CONNECT MT5 ACCOUNT
========================================================= */

app.post(
  '/api/mt5/accounts',
  requireUser,
  async (req, res) => {
    try {
      const {
        name,
        broker,
        server,
        login,
        password
      } = req.body || {};

      if (
        !name ||
        !server ||
        !login ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          error:
            'name, server, login and password are required'
        });
      }

      if (!providerConfigured()) {
        return res.status(503).json({
          ok: false,
          error:
            `${MT5_PROVIDER} provider is not configured`
        });
      }

      const loginString = String(login).trim();

      if (!/^[0-9]+$/.test(loginString)) {
        return res.status(400).json({
          ok: false,
          error: 'MT5 login must be numeric'
        });
      }

      /*
       * IMPORTANT:
       * password is used only for provider provisioning.
       * It is NOT saved in our PostgreSQL database.
       */

      const providerAccount =
        await providerCreateAccount({
          login: loginString,
          password: String(password),
          name: String(name),
          server: String(server)
        });

      const providerAccountId =
        providerAccount?.id ||
        providerAccount?.accountId ||
        providerAccount?.account?.id;

      if (!providerAccountId) {
        return res.status(502).json({
          ok: false,
          error:
            'Provider did not return an MT5 account ID'
        });
      }

      const result = await dbQuery(
        `
        INSERT INTO mt5_accounts
        (
          user_id,
          provider,
          provider_account_id,
          name,
          broker,
          server,
          platform,
          connection_status,
          state,
          login_masked
        )
        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          'mt5',
          'CREATED',
          'CREATED',
          $7
        )
        RETURNING
          id,
          provider,
          provider_account_id,
          name,
          broker,
          server,
          platform,
          connection_status,
          state,
          login_masked
        `,
        [
          req.userId,
          MT5_PROVIDER,
          String(providerAccountId),
          String(name),
          broker
            ? String(broker)
            : null,
          String(server),
          maskLogin(loginString)
        ]
      );

      const localAccount =
        result.rows[0];

      await audit(
        req.userId,
        'MT5_ACCOUNT_CREATED',
        {
          accountId: localAccount.id,
          provider: MT5_PROVIDER
        }
      );

      /*
       * Attempt provider deployment.
       *
       * If deployment fails, the account remains recorded,
       * but it is NOT reported as connected.
       */

      let deployment = null;

      try {
        deployment =
          await providerDeployAccount(
            String(providerAccountId)
          );
      } catch (deployError) {
        console.error(
          'Provider deployment:',
          deployError.message
        );
      }

      res.status(201).json({
        ok: true,
        account: localAccount,
        deployment: deployment
          ? {
              requested: true
            }
          : {
              requested: false
            },
        message:
          'MT5 account submitted. Synchronize the account to verify the real connection.'
      });
    } catch (error) {
      console.error(
        'MT5 connection error:',
        error.message
      );

      res.status(
        error.status >= 400 &&
        error.status < 600
          ? error.status
          : 500
      ).json({
        ok: false,
        error:
          error.message ||
          'Unable to connect MT5 account'
      });
    }
  }
);

/* =========================================================
   SYNC MT5 ACCOUNT
========================================================= */

app.post(
  '/api/mt5/accounts/:id/sync',
  requireUser,
  async (req, res) => {
    try {
      const result = await dbQuery(
        `
        SELECT *
        FROM mt5_accounts
        WHERE id = $1
          AND user_id = $2
        LIMIT 1
        `,
        [
          req.params.id,
          req.userId
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          ok: false,
          error: 'MT5 account not found'
        });
      }

      const account =
        result.rows[0];

      const providerAccount =
        await providerGetAccount(
          account.provider_account_id
        );

      const providerStatus =
        String(
          providerAccount?.connectionStatus ||
          providerAccount?.status ||
          ''
        ).toUpperCase();

      const connected =
        providerStatus === 'CONNECTED';

      let information = null;

      if (connected) {
        try {
          information =
            await providerAccountInformation(
              account.provider_account_id
            );
        } catch (infoError) {
          console.error(
            'Account information:',
            infoError.message
          );
        }
      }

      const connectionStatus =
        connected
          ? 'CONNECTED'
          : providerStatus ||
            'NOT_CONNECTED';

      const state =
        providerAccount?.state ||
        providerAccount?.connectionStatus ||
        null;

      const balance =
        safeNumber(
          information?.balance
        );

      const equity =
        safeNumber(
          information?.equity
        );

      const freeMargin =
        safeNumber(
          information?.freeMargin
        );

      const currency =
        information?.currency ||
        null;

      await dbQuery(
        `
        UPDATE mt5_accounts
        SET
          connection_status = $1,
          state = $2,
          balance = $3,
          equity = $4,
          free_margin = $5,
          currency = $6,
          last_sync = NOW(),
          updated_at = NOW()
        WHERE id = $7
          AND user_id = $8
        `,
        [
          connectionStatus,
          state,
          balance,
          equity,
          freeMargin,
          currency,
          account.id,
          req.userId
        ]
      );

      await audit(
        req.userId,
        'MT5_ACCOUNT_SYNC',
        {
          accountId: account.id,
          connectionStatus
        }
      );

      res.json({
        ok: true,
        verified: connected,
        account: {
          id: account.id,
          name: account.name,
          broker: account.broker,
          server: account.server,
          provider: account.provider,
          connectionStatus,
          state,
          balance,
          equity,
          freeMargin,
          currency,
          lastSync: new Date().toISOString()
        }
      });
    } catch (error) {
      console.error(
        'MT5 sync error:',
        error.message
      );

      res.status(500).json({
        ok: false,
        verified: false,
        error:
          error.message ||
          'MT5 synchronization failed'
      });
    }
  }
);

/* =========================================================
   REAL MT5 POSITIONS
========================================================= */

app.get(
  '/api/mt5/accounts/:id/positions',
  requireUser,
  async (req, res) => {
    try {
      const result = await dbQuery(
        `
        SELECT *
        FROM mt5_accounts
        WHERE id = $1
          AND user_id = $2
        LIMIT 1
        `,
        [
          req.params.id,
          req.userId
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          ok: false,
          error: 'MT5 account not found'
        });
      }

      const account =
        result.rows[0];

      if (
        account.connection_status !==
        'CONNECTED'
      ) {
        return res.status(409).json({
          ok: false,
          error:
            'MT5 account is not verified as connected',
          positions: []
        });
      }

      const positions =
        await providerPositions(
          account.provider_account_id
        );

      res.json({
        ok: true,
        positions:
          Array.isArray(positions)
            ? positions
            : positions?.positions || []
      });
    } catch (error) {
      console.error(
        'Positions error:',
        error.message
      );

      res.status(500).json({
        ok: false,
        error:
          'Unable to retrieve real MT5 positions'
      });
    }
  }
);

/* =========================================================
   TRADE
========================================================= */

app.post(
  '/api/trade',
  requireUser,
  async (req, res) => {
    try {
      /*
       * NEVER allow live trading just because the
       * frontend sends a button request.
       */

      if (!TRADING_ENABLED) {
        return res.status(403).json({
          ok: false,
          status: 'BLOCKED',
          error:
            'Live trading is currently disabled'
        });
      }

      const {
        accountId,
        actionType,
        symbol,
        volume,
        stopLoss,
        takeProfit,
        comment
      } = req.body || {};

      if (
        !accountId ||
        !actionType ||
        !symbol ||
        volume === undefined
      ) {
        return res.status(400).json({
          ok: false,
          error:
            'accountId, actionType, symbol and volume are required'
        });
      }

      const numericVolume =
        Number(volume);

      if (
        !Number.isFinite(numericVolume) ||
        numericVolume <= 0
      ) {
        return res.status(400).json({
          ok: false,
          error: 'Invalid trade volume'
        });
      }

      const result = await dbQuery(
        `
        SELECT *
        FROM mt5_accounts
        WHERE id = $1
          AND user_id = $2
        LIMIT 1
        `,
        [
          accountId,
          req.userId
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          ok: false,
          error: 'MT5 account not found'
        });
      }

      const account =
        result.rows[0];

      if (
        account.connection_status !==
        'CONNECTED'
      ) {
        return res.status(409).json({
          ok: false,
          status: 'BLOCKED',
          error:
            'MT5 is not connected. Trade was not sent.'
        });
      }

      /*
       * Current execution layer.
       *
       * Risk controls must be completed before
       * TRADING_ENABLED is turned on in production.
       */

      const marginPayload = {
        type:
          String(actionType).toLowerCase(),
        symbol: String(symbol),
        volume: numericVolume
      };

      let marginResult;

      try {
        marginResult =
          await providerCalculateMargin(
            account.provider_account_id,
            marginPayload
          );
      } catch (marginError) {
        await audit(
          req.userId,
          'TRADE_BLOCKED_MARGIN_CHECK',
          {
            accountId,
            symbol
          }
        );

        return res.status(409).json({
          ok: false,
          status: 'BLOCKED',
          error:
            'Broker margin validation failed. Trade was not sent.'
        });
      }

      const accountInfo =
        await providerAccountInformation(
          account.provider_account_id
        );

      const freeMargin =
        safeNumber(
          accountInfo?.freeMargin
        );

      const requiredMargin =
        safeNumber(
          marginResult?.margin ||
          marginResult?.requiredMargin
        );

      if (
        freeMargin !== null &&
        requiredMargin !== null &&
        requiredMargin > freeMargin
      ) {
        await audit(
          req.userId,
          'TRADE_BLOCKED_MARGIN',
          {
            accountId,
            symbol,
            requiredMargin,
            freeMargin
          }
        );

        return res.status(409).json({
          ok: false,
          status: 'BLOCKED',
          error:
            'Insufficient free margin. Trade was not sent.'
        });
      }

      const tradePayload = {
        actionType:
          String(actionType),
        symbol:
          String(symbol),
        volume:
          numericVolume
      };

      if (
        stopLoss !== undefined &&
        stopLoss !== null &&
        stopLoss !== ''
      ) {
        tradePayload.stopLoss =
          Number(stopLoss);
      }

      if (
        takeProfit !== undefined &&
        takeProfit !== null &&
        takeProfit !== ''
      ) {
        tradePayload.takeProfit =
          Number(takeProfit);
      }

      if (comment) {
        tradePayload.comment =
          String(comment).slice(0, 100);
      }

      const brokerResponse =
        await providerTrade(
          account.provider_account_id,
          tradePayload
        );

      /*
       * Do NOT report success merely because the HTTP
       * request returned 200.
       */

      const stringCode =
        String(
          brokerResponse?.stringCode ||
          brokerResponse?.retcode ||
          brokerResponse?.code ||
          ''
        ).toUpperCase();

      const successful =
        stringCode ===
          'TRADE_RETCODE_DONE' ||
        stringCode === 'DONE' ||
        brokerResponse?.success === true;

      const tradeStatus =
        successful
          ? 'SUCCESS'
          : 'REJECTED';

      const orderId =
        brokerResponse?.orderId ||
        brokerResponse?.order ||
        brokerResponse?.positionId ||
        null;

      await dbQuery(
        `
        INSERT INTO trades
        (
          user_id,
          mt5_account_id,
          action_type,
          symbol,
          volume,
          order_id,
          broker_code,
          broker_message,
          status
        )
        VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        `,
        [
          req.userId,
          account.id,
          String(actionType),
          String(symbol),
          numericVolume,
          orderId
            ? String(orderId)
            : null,
          stringCode || null,
          brokerResponse?.message
            ? String(
                brokerResponse.message
              ).slice(0, 1000)
            : null,
          tradeStatus
        ]
      );

      await audit(
        req.userId,
        successful
          ? 'TRADE_EXECUTED'
          : 'TRADE_REJECTED',
        {
          accountId,
          symbol,
          volume: numericVolume,
          orderId
        }
      );

      if (!successful) {
        return res.status(409).json({
          ok: false,
          status: 'REJECTED',
          error:
            brokerResponse?.message ||
            'Broker rejected the trade',
          broker: brokerResponse
        });
      }

      res.json({
        ok: true,
        status: 'SUCCESS',
        orderId,
        broker: brokerResponse
      });
    } catch (error) {
      console.error(
        'Trade error:',
        error.message
      );

      res.status(500).json({
        ok: false,
        status: 'ERROR',
        error:
          'Trade execution failed. No success was reported.'
      });
    }
  }
);

/* =========================================================
   USER TRADE HISTORY
========================================================= */

app.get(
  '/api/trades',
  requireUser,
  async (req, res) => {
    try {
      const result = await dbQuery(
        `
        SELECT
          id,
          mt5_account_id,
          action_type,
          symbol,
          volume,
          order_id,
          broker_code,
          broker_message,
          status,
          created_at
        FROM trades
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 500
        `,
        [req.userId]
      );

      res.json({
        ok: true,
        trades: result.rows
      });
    } catch (error) {
      res.status(500).json({
        ok: false,
        error: 'Unable to load trade history'
      });
    }
  }
);

/* =========================================================
   PUBLISHED BOTS
========================================================= */

app.get(
  '/api/bots',
  requireUser,
  async (req, res) => {
    try {
      const result = await dbQuery(
        `
        SELECT
          id,
          name,
          description,
          version,
          status,
          image_url,
          file_url,
          created_at,
          updated_at
        FROM bots
        WHERE status = 'PUBLISHED'
        ORDER BY created_at DESC
        `
      );

      res.json({
        ok: true,
        bots: result.rows
      });
    } catch (error) {
      res.status(500).json({
        ok: false,
        error: 'Unable to load bots'
      });
    }
  }
);

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
  '/api/admin/login',
  async (req, res) => {
    try {
      const email =
        String(
          req.body?.email || ''
        ).trim();

      const password =
        String(
          req.body?.password || ''
        );

      if (
        !ADMIN_EMAIL ||
        !ADMIN_PASSWORD ||
        !ADMIN_JWT_SECRET
      ) {
        return res.status(503).json({
          ok: false,
          error:
            'Admin authentication is not configured'
        });
      }

      if (
        email !== ADMIN_EMAIL ||
        password !== ADMIN_PASSWORD
      ) {
        return res.status(401).json({
          ok: false,
          error:
            'Invalid administrator credentials'
        });
      }

      const token =
        signAdminToken();

      res.json({
        ok: true,
        token,
        admin: {
          email: ADMIN_EMAIL
        }
      });
    } catch (error) {
      res.status(500).json({
        ok: false,
        error: 'Admin login failed'
      });
    }
  }
);

/* =========================================================
   ADMIN ME
========================================================= */

app.get(
  '/api/admin/me',
  requireAdmin,
  async (req, res) => {
    res.json({
      ok: true,
      admin: {
        email: req.adminEmail
      }
    });
  }
);

/* =========================================================
   ADMIN DASHBOARD
========================================================= */

app.get(
  '/api/admin/dashboard',
  requireAdmin,
  async (req, res) => {
    try {
      const [
        users,
        mt5Accounts,
        connectedMt5,
        bots,
        publishedBots,
        tradesToday,
        failedTrades
      ] = await Promise.all([
        dbQuery(
          `SELECT COUNT(*)::int AS count FROM users`
        ),

        dbQuery(
          `SELECT COUNT(*)::int AS count FROM mt5_accounts`
        ),

        dbQuery(
          `
          SELECT COUNT(*)::int AS count
          FROM mt5_accounts
          WHERE connection_status = 'CONNECTED'
          `
        ),

        dbQuery(
          `SELECT COUNT(*)::int AS count FROM bots`
        ),

        dbQuery(
          `
          SELECT COUNT(*)::int AS count
          FROM bots
          WHERE status = 'PUBLISHED'
          `
        ),

        dbQuery(
          `
          SELECT COUNT(*)::int AS count
          FROM trades
          WHERE created_at >= CURRENT_DATE
          `
        ),

        dbQuery(
          `
          SELECT COUNT(*)::int AS count
          FROM trades
          WHERE created_at >= CURRENT_DATE
            AND status IN ('REJECTED','ERROR')
          `
        )
      ]);

      res.json({
        ok: true,

        cloud: {
          status: 'ONLINE'
        },

        mt5: {
          provider: MT5_PROVIDER,
          configured: providerConfigured(),
          connectedAccounts:
            connectedMt5.rows[0].count
        },

        trading: {
          enabled: TRADING_ENABLED
        },

        counts: {
          users:
            users.rows[0].count,

          mt5Accounts:
            mt5Accounts.rows[0].count,

          bots:
            bots.rows[0].count,

          publishedBots:
            publishedBots.rows[0].count,

          tradesToday:
            tradesToday.rows[0].count,

          failedTradesToday:
            failedTrades.rows[0].count
        },

        timestamp:
          new Date().toISOString()
      });
    } catch (error) {
      console.error(
        'Admin dashboard:',
        error.message
      );

      res.status(500).json({
        ok: false,
        error:
          'Unable to load administrator dashboard'
      });
    }
  }
);

/* =========================================================
   ADMIN MT5 ACCOUNTS
========================================================= */

app.get(
  '/api/admin/mt5-accounts',
  requireAdmin,
  async (req, res) => {
    try {
      const result = await dbQuery(
        `
        SELECT
          a.id,
          a.user_id,
          a.provider,
          a.name,
          a.broker,
          a.server,
          a.platform,
          a.connection_status,
          a.state,
          a.login_masked,
          a.balance,
          a.equity,
          a.free_margin,
          a.currency,
          a.last_sync,
          a.created_at
        FROM mt5_accounts a
        ORDER BY a.created_at DESC
        LIMIT 1000
        `
      );

      res.json({
        ok: true,
        accounts: result.rows
      });
    } catch (error) {
      res.status(500).json({
        ok: false,
        error:
          'Unable to load MT5 accounts'
      });
    }
  }
);

/* =========================================================
   ADMIN TRADES
========================================================= */

app.get(
  '/api/admin/trades',
  requireAdmin,
  async (req, res) => {
    try {
      const result = await dbQuery(
        `
        SELECT
          id,
          user_id,
          mt5_account_id,
          action_type,
          symbol,
          volume,
          order_id,
          broker_code,
          broker_message,
          status,
          created_at
        FROM trades
        ORDER BY created_at DESC
        LIMIT 1000
        `
      );

      res.json({
        ok: true,
        trades: result.rows
      });
    } catch (error) {
      res.status(500).json({
        ok: false,
        error:
          'Unable to load trading activity'
      });
    }
  }
);

/* =========================================================
   ADMIN BOTS
========================================================= */

app.get(
  '/api/admin/bots',
  requireAdmin,
  async (req, res) => {
    try {
      const result = await dbQuery(
        `
        SELECT
          id,
          name,
          description,
          version,
          status,
          image_url,
          file_url,
          created_at,
          updated_at
        FROM bots
        ORDER BY created_at DESC
        `
      );

      res.json({
        ok: true,
        bots: result.rows
      });
    } catch (error) {
      res.status(500).json({
        ok: false,
        error: 'Unable to load bots'
      });
    }
  }
);

/* =========================================================
   ADMIN CREATE BOT
========================================================= */

app.post(
  '/api/admin/bots',
  requireAdmin,
  async (req, res) => {
    try {
      const {
        name,
        description,
        version,
        status,
        imageUrl,
        fileUrl
      } = req.body || {};

      if (!name) {
        return res.status(400).json({
          ok: false,
          error: 'Bot name is required'
        });
      }

      const allowedStatuses = [
        'DRAFT',
        'PUBLISHED',
        'DISABLED'
      ];

      const botStatus =
        allowedStatuses.includes(
          String(status || '').toUpperCase()
        )
          ? String(status).toUpperCase()
          : 'DRAFT';

      const result = await dbQuery(
        `
        INSERT INTO bots
        (
          name,
          description,
          version,
          status,
          image_url,
          file_url
        )
        VALUES
        ($1,$2,$3,$4,$5,$6)
        RETURNING *
        `,
        [
          String(name),
          description
            ? String(description)
            : null,
          version
            ? String(version)
            : '1.0.0',
          botStatus,
          imageUrl
            ? String(imageUrl)
            : null,
          fileUrl
            ? String(fileUrl)
            : null
        ]
      );

      res.status(201).json({
        ok: true,
        bot: result.rows[0]
      });
    } catch (error) {
      console.error(
        'Create bot:',
        error.message
      );

      res.status(500).json({
        ok: false,
        error:
          'Unable to create bot'
      });
    }
  }
);

/* =========================================================
   ADMIN UPDATE BOT
========================================================= */

app.patch(
  '/api/admin/bots/:id',
  requireAdmin,
  async (req, res) => {
    try {
      const {
        name,
        description,
        version,
        status,
        imageUrl,
        fileUrl
      } = req.body || {};

      const allowedStatuses = [
        'DRAFT',
        'PUBLISHED',
        'DISABLED'
      ];

      let botStatus = null;

      if (status !== undefined) {
        const normalized =
          String(status).toUpperCase();

        if (
          !allowedStatuses.includes(
            normalized
          )
        ) {
          return res.status(400).json({
            ok: false,
            error: 'Invalid bot status'
          });
        }

        botStatus = normalized;
      }

      const result = await dbQuery(
        `
        UPDATE bots
        SET
          name = COALESCE($1, name),
          description = COALESCE($2, description),
          version = COALESCE($3, version),
          status = COALESCE($4, status),
          image_url = COALESCE($5, image_url),
          file_url = COALESCE($6, file_url),
          updated_at = NOW()
        WHERE id = $7
        RETURNING *
        `,
        [
          name !== undefined
            ? String(name)
            : null,

          description !== undefined
            ? String(description)
            : null,

          version !== undefined
            ? String(version)
            : null,

          botStatus,

          imageUrl !== undefined
            ? String(imageUrl)
            : null,

          fileUrl !== undefined
            ? String(fileUrl)
            : null,

          req.params.id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          ok: false,
          error: 'Bot not found'
        });
      }

      res.json({
        ok: true,
        bot: result.rows[0]
      });
    } catch (error) {
      console.error(
        'Update bot:',
        error.message
      );

      res.status(500).json({
        ok: false,
        error:
          'Unable to update bot'
      });
    }
  }
);

/* =========================================================
   ADMIN DELETE BOT
========================================================= */

app.delete(
  '/api/admin/bots/:id',
  requireAdmin,
  async (req, res) => {
    try {
      const result = await dbQuery(
        `
        DELETE FROM bots
        WHERE id = $1
        RETURNING id
        `,
        [req.params.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          ok: false,
          error: 'Bot not found'
        });
      }

      res.json({
        ok: true,
        deleted: true,
        id: result.rows[0].id
      });
    } catch (error) {
      res.status(500).json({
        ok: false,
        error:
          'Unable to delete bot'
      });
    }
  }
);

/* =========================================================
   404
========================================================= */

app.use(
  '/api',
  (req, res) => {
    res.status(404).json({
      ok: false,
      error: 'API endpoint not found',
      path: req.path
    });
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      'Server error:',
      error.message
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      ok: false,
      error:
        NODE_ENV === 'production'
          ? 'Internal server error'
          : error.message
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await initializeDatabase();

    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          `ELISY254 CLOUD backend running on port ${PORT}`
        );

        console.log(
          `MT5 provider: ${MT5_PROVIDER}`
        );

        console.log(
          `MT5 provider configured: ${providerConfigured()}`
        );

        console.log(
          `Live trading enabled: ${TRADING_ENABLED}`
        );
      }
    );
  } catch (error) {
    console.error(
      'SERVER STARTUP FAILED:',
      error
    );

    process.exit(1);
  }
}

startServer();
