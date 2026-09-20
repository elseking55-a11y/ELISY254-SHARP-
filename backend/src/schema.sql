CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE,
  access_key_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'USER',
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mt5_accounts (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  metaapi_account_id TEXT UNIQUE NOT NULL,
  login TEXT,
  server TEXT,
  platform TEXT NOT NULL DEFAULT 'mt5',
  status TEXT NOT NULL DEFAULT 'PENDING',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS risk_settings (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,

  martingale_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  recovery_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  daily_loss_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  stop_loss_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  take_profit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  trade_size_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  margin_check_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  max_positions_enabled BOOLEAN NOT NULL DEFAULT TRUE,

  risk_percent NUMERIC(10,4) NOT NULL DEFAULT 0.5,
  daily_loss_percent NUMERIC(10,4) NOT NULL DEFAULT 2,
  max_positions INTEGER NOT NULL DEFAULT 1,

  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS bots (
  id UUID PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'DRAFT',
  analysis_mode TEXT NOT NULL DEFAULT 'ENGINE',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_bots (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  bot_id UUID NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
  active BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (user_id, bot_id)
);

CREATE TABLE IF NOT EXISTS trades (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id UUID NOT NULL REFERENCES mt5_accounts(id) ON DELETE CASCADE,

  symbol TEXT NOT NULL,
  side TEXT NOT NULL,
  volume NUMERIC(18,8) NOT NULL,

  stop_loss NUMERIC(18,8),
  take_profit NUMERIC(18,8),

  mt5_order_id TEXT,
  status TEXT NOT NULL,

  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  executed_at TIMESTAMPTZ,
  error_message TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY,
  user_id UUID,
  action TEXT NOT NULL,
  details JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO bots (
  id,
  name,
  description,
  status,
  analysis_mode
)
VALUES (
  gen_random_uuid(),
  'ELISY254 ENGINE',
  'Account-aware trading engine',
  'PUBLISHED',
  'ENGINE'
)
ON CONFLICT (name) DO NOTHING;
