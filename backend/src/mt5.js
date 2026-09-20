let metaApiModule = null;
let metaApiClient = null;

/**
 * MetaApi is OPTIONAL.
 *
 * The backend can start without:
 * - METAAPI_TOKEN
 * - MT5 terminal
 *
 * MetaApi is loaded only when it is actually needed.
 */

export function isMetaApiConfigured() {
  return Boolean(
    String(process.env.METAAPI_TOKEN || "").trim()
  );
}

export function isTerminalConfigured() {
  return Boolean(
    String(process.env.TERMINAL_BRIDGE_URL || "").trim()
  );
}

export function getMt5Provider() {
  return String(
    process.env.MT5_PROVIDER || "AUTO"
  ).toUpperCase();
}

async function getMetaApi() {
  if (!isMetaApiConfigured()) {
    throw new Error(
      "MetaApi is not configured"
    );
  }

  /*
   * IMPORTANT:
   * Do NOT import MetaApi at server startup.
   *
   * This dynamic import means Render can start
   * even when MetaApi is not configured.
   */
  if (!metaApiModule) {
    metaApiModule =
      await import("metaapi.cloud-sdk");
  }

  const MetaApi =
    metaApiModule.default ||
    metaApiModule.MetaApi;

  if (!MetaApi) {
    throw new Error(
      "MetaApi SDK could not be loaded"
    );
  }

  if (!metaApiClient) {
    metaApiClient =
      new MetaApi(
        String(
          process.env.METAAPI_TOKEN
        ).trim()
      );
  }

  return metaApiClient;
}

/**
 * Returns the current configured connection
 * possibilities.
 *
 * This does NOT pretend MT5 is connected.
 */
export function getConnectionStatus() {
  const metaApi =
    isMetaApiConfigured();

  const terminal =
    isTerminalConfigured();

  return {
    provider: getMt5Provider(),

    metaApiConfigured:
      metaApi,

    terminalConfigured:
      terminal,

    status: "NOT_CONNECTED"
  };
}

/**
 * Get MetaApi account object.
 */
export async function getAccount(
  metaApiAccountId
) {
  const api =
    await getMetaApi();

  if (!metaApiAccountId) {
    throw new Error(
      "MetaApi account ID is required"
    );
  }

  return api
    .metatraderAccountApi
    .getAccount(
      metaApiAccountId
    );
}

/**
 * Get real MT5 account information.
 */
export async function getAccountInformation(
  metaApiAccountId
) {
  const account =
    await getAccount(
      metaApiAccountId
    );

  const connection =
    account.getRPCConnection();

  await connection.connect();

  await connection.waitSynchronized();

  return connection
    .getAccountInformation();
}

/**
 * Get real MT5 positions.
 */
export async function getPositions(
  metaApiAccountId
) {
  const account =
    await getAccount(
      metaApiAccountId
    );

  const connection =
    account.getRPCConnection();

  await connection.connect();

  await connection.waitSynchronized();

  return connection.getPositions();
}

/**
 * Real market BUY.
 *
 * This function must NEVER be called unless:
 * - trading is enabled
 * - MT5 account exists
 * - risk checks have passed
 */
export async function createMarketBuyOrder({
  accountId,
  symbol,
  volume,
  stopLoss,
  takeProfit
}) {
  if (!isMetaApiConfigured()) {
    throw new Error(
      "MT5 is not connected. MetaApi is not configured."
    );
  }

  if (!accountId) {
    throw new Error(
      "MT5 account is required"
    );
  }

  if (!symbol) {
    throw new Error(
      "Trading symbol is required"
    );
  }

  const numericVolume =
    Number(volume);

  if (
    !Number.isFinite(
      numericVolume
    ) ||
    numericVolume <= 0
  ) {
    throw new Error(
      "Invalid trade volume"
    );
  }

  const account =
    await getAccount(
      accountId
    );

  const connection =
    account.getRPCConnection();

  await connection.connect();

  await connection.waitSynchronized();

  return connection
    .createMarketBuyOrder(
      symbol,
      numericVolume,
      stopLoss,
      takeProfit
    );
}

/**
 * Real market SELL.
 */
export async function createMarketSellOrder({
  accountId,
  symbol,
  volume,
  stopLoss,
  takeProfit
}) {
  if (!isMetaApiConfigured()) {
    throw new Error(
      "MT5 is not connected. MetaApi is not configured."
    );
  }

  if (!accountId) {
    throw new Error(
      "MT5 account is required"
    );
  }

  if (!symbol) {
    throw new Error(
      "Trading symbol is required"
    );
  }

  const numericVolume =
    Number(volume);

  if (
    !Number.isFinite(
      numericVolume
    ) ||
    numericVolume <= 0
  ) {
    throw new Error(
      "Invalid trade volume"
    );
  }

  const account =
    await getAccount(
      accountId
    );

  const connection =
    account.getRPCConnection();

  await connection.connect();

  await connection.waitSynchronized();

  return connection
    .createMarketSellOrder(
      symbol,
      numericVolume,
      stopLoss,
      takeProfit
    );
}

/**
 * Generic market order.
 */
export async function createMarketOrder({
  accountId,
  side,
  symbol,
  volume,
  stopLoss,
  takeProfit
}) {
  const normalizedSide =
    String(side || "")
      .toUpperCase();

  if (
    normalizedSide !== "BUY" &&
    normalizedSide !== "SELL"
  ) {
    throw new Error(
      "Invalid trade side. Use BUY or SELL."
    );
  }

  if (normalizedSide === "BUY") {
    return createMarketBuyOrder({
      accountId,
      symbol,
      volume,
      stopLoss,
      takeProfit
    });
  }

  return createMarketSellOrder({
    accountId,
    symbol,
    volume,
    stopLoss,
    takeProfit
  });
}
