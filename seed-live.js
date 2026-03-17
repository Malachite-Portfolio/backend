require("dotenv").config();

const { Pool } = require("pg");
const { createSeedState, normalizeState, SEEDED_ADMIN, SEEDED_HOSTS, SEEDED_USERS } = require("./state");

const DATABASE_URL = process.env.DATABASE_URL || "";
const DATABASE_SSL = process.env.DATABASE_SSL === "true";

async function run() {
  if (!DATABASE_URL) {
    throw new Error("DATABASE_URL is required.");
  }

  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: DATABASE_SSL ? { rejectUnauthorized: false } : false,
  });

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS platform_state (
        id SMALLINT PRIMARY KEY DEFAULT 1,
        state JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS platform_events (
        id BIGSERIAL PRIMARY KEY,
        event_type TEXT NOT NULL,
        actor_id TEXT,
        actor_role TEXT,
        payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    const state = normalizeState(createSeedState());
    await pool.query(
      `
      INSERT INTO platform_state (id, state, updated_at)
      VALUES (1, $1::jsonb, NOW())
      ON CONFLICT (id)
      DO UPDATE SET state = EXCLUDED.state, updated_at = NOW();
      `,
      [JSON.stringify(state)]
    );

    await pool.query("DELETE FROM platform_events;");

    console.log("Live seed completed.");
    console.log("Demo user phones:", SEEDED_USERS.map((entry) => entry.phone).join(", "));
    console.log("Demo host phones:", SEEDED_HOSTS.map((entry) => entry.phone).join(", "));
    console.log("Demo OTP (when DEMO_MODE=true):", process.env.DEMO_FIXED_OTP || "123456");
    console.log("Admin login:", SEEDED_ADMIN.email, "/ Admin@12345");
  } finally {
    await pool.end();
  }
}

run().catch((error) => {
  console.error("Seed failed:", error.message);
  process.exit(1);
});
