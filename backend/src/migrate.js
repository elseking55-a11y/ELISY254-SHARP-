import "dotenv/config";
import { readFile } from "fs/promises";
import { pool } from "./db.js";

async function migrate() {
  console.log("=================================");
  console.log("ELISY254 CLOUD DATABASE SETUP");
  console.log("=================================");

  try {
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL is missing");
    }

    const schema = await readFile(
      new URL("./schema.sql", import.meta.url),
      "utf8"
    );

    await pool.query(schema);

    console.log("DATABASE INITIALIZATION: SUCCESS");
    console.log("Tables are ready.");
  } catch (error) {
    console.error("DATABASE INITIALIZATION: FAILED");
    console.error(error.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

await migrate();
