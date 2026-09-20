export function validateRiskSettings(settings) {
  const risk = Number(settings.risk_percent);
  const daily = Number(settings.daily_loss_percent);
  const positions = Number(settings.max_positions);

  if (!Number.isFinite(risk) || risk <= 0) {
    throw new Error("Invalid risk percentage");
  }

  if (!Number.isFinite(daily) || daily <= 0) {
    throw new Error("Invalid daily loss percentage");
  }

  if (!Number.isInteger(positions) || positions < 1) {
    throw new Error("Invalid maximum positions");
  }

  if (risk > Number(process.env.MAX_RISK_PERCENT || 5)) {
    throw new Error("Risk percentage exceeds platform limit");
  }

  if (
    daily >
    Number(process.env.MAX_DAILY_LOSS_PERCENT || 20)
  ) {
    throw new Error("Daily loss limit exceeds platform limit");
  }

  return true;
}

export function calculateRiskMoney(
  balance,
  riskPercent
) {
  const b = Number(balance);
  const r = Number(riskPercent);

  if (!Number.isFinite(b) || b <= 0) {
    throw new Error("Invalid account balance");
  }

  return b * (r / 100);
}

export function checkDailyLoss(
  startingBalance,
  currentEquity,
  maxDailyLossPercent
) {
  const start = Number(startingBalance);
  const equity = Number(currentEquity);
  const limit = Number(maxDailyLossPercent);

  if (
    !Number.isFinite(start) ||
    !Number.isFinite(equity)
  ) {
    throw new Error("Invalid account values");
  }

  const lossPercent =
    ((start - equity) / start) * 100;

  return {
    lossPercent,
    allowed: lossPercent < limit
  };
}
