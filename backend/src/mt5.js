import MetaApi from "metaapi.cloud-sdk";

let api;

function getApi() {
  if (!process.env.METAAPI_TOKEN) {
    throw new Error("METAAPI_TOKEN is not configured");
  }

  if (!api) {
    api = new MetaApi(
      process.env.METAAPI_TOKEN
    );
  }

  return api;
}

export async function getAccount(
  metaApiAccountId
) {
  const account = await getApi()
    .metatraderAccountApi
    .getAccount(metaApiAccountId);

  return account;
}

export async function getAccountInformation(
  metaApiAccountId
) {
  const account = await getAccount(
    metaApiAccountId
  );

  const connection =
    account.getRPCConnection();

  await connection.connect();

  await connection.waitSynchronized();

  return connection.getAccountInformation();
}

export async function getPositions(
  metaApiAccountId
) {
  const account = await getAccount(
    metaApiAccountId
  );

  const connection =
    account.getRPCConnection();

  await connection.connect();

  await connection.waitSynchronized();

  return connection.getPositions();
}

export async function createMarketOrder({
  accountId,
  side,
  symbol,
  volume,
  stopLoss,
  takeProfit
}) {
  if (!["BUY", "SELL"].includes(side)) {
    throw new Error("Invalid trade side");
  }

  if (!Number.isFinite(Number(volume)) ||
      Number(volume) <= 0) {
    throw new Error("Invalid trade volume");
  }

  const account =
    await getAccount(accountId);

  const connection =
    account.getRPCConnection();

  await connection.connect();

  await connection.waitSynchronized();

  const result =
    side === "BUY"
      ? await connection.createMarketBuyOrder(
          symbol,
          Number(volume),
          stopLoss,
          takeProfit
        )
      : await connection.createMarketSellOrder(
          symbol,
          Number(volume),
          stopLoss,
          takeProfit
        );

  return result;
    }
