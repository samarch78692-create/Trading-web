const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");

const app = express();

// Abasthan provides PORT automatically.
// 10000 is used only as a fallback.
const PORT = Number(process.env.PORT) || 10000;

// Only required environment variable.
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is missing.");
  process.exit(1);
}

/*
  JWT secret is generated automatically.

  This means you do NOT need JWT_SECRET in Abasthan.
  Important: users will need to log in again after a server restart.
*/
const JWT_SECRET = crypto.randomBytes(48).toString("hex");

// PostgreSQL / Neon connection
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false },

  // Don't wait forever if Neon is unavailable.
  connectionTimeoutMillis: 10000,

  // Keep the pool small for a small educational website.
  max: 5,

  idleTimeoutMillis: 30000
});

pool.on("error", (error) => {
  console.error("PostgreSQL pool error:", error);
});

const publicPath = path.join(__dirname, "public");
const indexPath = path.join(publicPath, "index.html");

app.disable("x-powered-by");

app.use(express.json({ limit: "1mb" }));

// Serve website files
app.use(
  express.static(publicPath, {
    index: "index.html",
    maxAge: "1h"
  })
);

// ----------------------------------------------------
// DATABASE STATE
// ----------------------------------------------------

let databaseReady = false;

// ----------------------------------------------------
// AUTHENTICATION
// ----------------------------------------------------

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Login required"
      });
    }

    const token = header.substring(7);

    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Login required"
    });
  }
}

function owner(req, res, next) {
  if (!req.user || req.user.role !== "owner") {
    return res.status(403).json({
      error: "Owner only"
    });
  }

  next();
}

function requireDatabase(req, res, next) {
  if (!databaseReady) {
    return res.status(503).json({
      error: "Database is currently unavailable. Please try again shortly."
    });
  }

  next();
}

// ----------------------------------------------------
// HEALTH CHECK
// ----------------------------------------------------

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    databaseReady = true;

    res.status(200).json({
      ok: true,
      server: true,
      database: true
    });
  } catch (error) {
    databaseReady = false;

    console.error("Health database check failed:", error.message);

    res.status(503).json({
      ok: false,
      server: true,
      database: false
    });
  }
});

// Simple server test that DOES NOT require Neon
app.get("/server-test", (req, res) => {
  res.status(200).send("TradeSmart server is running.");
});

// ----------------------------------------------------
// LOGIN
// ----------------------------------------------------

app.post("/api/login", requireDatabase, async (req, res) => {
  try {
    const email = String(req.body?.email || "")
      .toLowerCase()
      .trim();

    const password = String(req.body?.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password required"
      });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        error: "Invalid credentials"
      });
    }

    const user = result.rows[0];

    const passwordMatch = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatch) {
      return res.status(401).json({
        error: "Invalid credentials"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// ----------------------------------------------------
// CURRENT USER
// ----------------------------------------------------

app.get("/api/me", auth, (req, res) => {
  res.json({
    user: req.user
  });
});

// ----------------------------------------------------
// LECTURES
// ----------------------------------------------------

app.get("/api/lectures", requireDatabase, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
        id,
        module_no,
        level,
        title,
        description,
        video_url,
        created_at
       FROM lectures
       ORDER BY module_no ASC, id ASC`
    );

    res.json({
      lectures: result.rows
    });
  } catch (error) {
    console.error("Lectures fetch error:", error);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// ----------------------------------------------------
// STUDENTS
// ----------------------------------------------------

app.get(
  "/api/students",
  requireDatabase,
  auth,
  owner,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
          id,
          email,
          created_at
         FROM users
         WHERE role='student'
         ORDER BY id DESC`
      );

      res.json({
        students: result.rows
      });
    } catch (error) {
      console.error("Students fetch error:", error);

      res.status(500).json({
        error: "Server error"
      });
    }
  }
);

app.post(
  "/api/students",
  requireDatabase,
  auth,
  owner,
  async (req, res) => {
    try {
      const email = String(req.body?.email || "")
        .toLowerCase()
        .trim();

      const password = String(req.body?.password || "");

      if (!email || !email.includes("@")) {
        return res.status(400).json({
          error: "Valid email required"
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error: "Password must be at least 6 characters"
        });
      }

      const passwordHash = await bcrypt.hash(password, 10);

      await pool.query(
        `INSERT INTO users
          (email, password_hash, role)
         VALUES
          ($1, $2, 'student')`,
        [email, passwordHash]
      );

      res.status(201).json({
        ok: true
      });
    } catch (error) {
      console.error("Student creation error:", error);

      if (error.code === "23505") {
        return res.status(400).json({
          error: "Email already exists"
        });
      }

      res.status(500).json({
        error: "Server error"
      });
    }
  }
);

app.delete(
  "/api/students/:id",
  requireDatabase,
  auth,
  owner,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error: "Invalid student ID"
        });
      }

      await pool.query(
        `DELETE FROM users
         WHERE id=$1 AND role='student'`,
        [id]
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error("Student deletion error:", error);

      res.status(500).json({
        error: "Server error"
      });
    }
  }
);

// ----------------------------------------------------
// LECTURE ADMINISTRATION
// ----------------------------------------------------

app.post(
  "/api/lectures",
  requireDatabase,
  auth,
  owner,
  async (req, res) => {
    try {
      const moduleNo = Number(req.body?.module_no);

      const level = String(
        req.body?.level || ""
      ).trim();

      const title = String(
        req.body?.title || ""
      ).trim();

      const description = String(
        req.body?.description || ""
      ).trim();

      const videoUrl = String(
        req.body?.video_url || ""
      ).trim();

      if (!Number.isInteger(moduleNo) || moduleNo < 1) {
        return res.status(400).json({
          error: "Valid module number required"
        });
      }

      if (!level) {
        return res.status(400).json({
          error: "Level required"
        });
      }

      if (!title) {
        return res.status(400).json({
          error: "Lecture title required"
        });
      }

      await pool.query(
        `INSERT INTO lectures
          (module_no, level, title, description, video_url)
         VALUES
          ($1, $2, $3, $4, $5)`,
        [
          moduleNo,
          level,
          title,
          description,
          videoUrl
        ]
      );

      res.status(201).json({
        ok: true
      });
    } catch (error) {
      console.error("Lecture creation error:", error);

      res.status(500).json({
        error: "Server error"
      });
    }
  }
);

app.delete(
  "/api/lectures/:id",
  requireDatabase,
  auth,
  owner,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error: "Invalid lecture ID"
        });
      }

      await pool.query(
        "DELETE FROM lectures WHERE id=$1",
        [id]
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error("Lecture deletion error:", error);

      res.status(500).json({
        error: "Server error"
      });
    }
  }
);

// ----------------------------------------------------
// OWNER SETUP
// ----------------------------------------------------

/*
  First-owner setup.

  No OWNER_EMAIL / OWNER_PASSWORD variables are required.

  When the database has no owner, the server generates
  a temporary setup code and prints it in the deployment logs.

  Use the setup endpoint ONCE to create the owner account.

  After an owner exists, this endpoint becomes disabled.
*/

let setupCode = null;

function generateSetupCode() {
  setupCode = crypto.randomBytes(24).toString("hex");

  console.log("");
  console.log("==============================================");
  console.log("TRADESMART OWNER SETUP");
  console.log("==============================================");
  console.log("Temporary setup code:");
  console.log(setupCode);
  console.log("Use it ONCE to create the owner account.");
  console.log("==============================================");
  console.log("");
}

app.post("/api/setup-owner", requireDatabase, async (req, res) => {
  try {
    if (!setupCode) {
      return res.status(403).json({
        error: "Owner setup is disabled."
      });
    }

    const suppliedCode = String(
      req.body?.setup_code || ""
    );

    if (suppliedCode !== setupCode) {
      return res.status(403).json({
        error: "Invalid setup code."
      });
    }

    const email = String(
      req.body?.email || ""
    )
      .toLowerCase()
      .trim();

    const password = String(
      req.body?.password || ""
    );

    if (!email || !email.includes("@")) {
      return res.status(400).json({
        error: "Valid owner email required."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Owner password must be at least 8 characters."
      });
    }

    const existingOwner = await pool.query(
      `SELECT id FROM users WHERE role='owner' LIMIT 1`
    );

    if (existingOwner.rowCount > 0) {
      setupCode = null;

      return res.status(403).json({
        error: "Owner already exists."
      });
    }

    const passwordHash = await bcrypt.hash(
      password,
      12
    );

    await pool.query(
      `INSERT INTO users
        (email, password_hash, role)
       VALUES
        ($1, $2, 'owner')`,
      [email, passwordHash]
    );

    setupCode = null;

    console.log(
      "Owner account successfully created."
    );

    res.status(201).json({
      ok: true,
      message: "Owner account created successfully."
    });
  } catch (error) {
    console.error("Owner setup error:", error);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// ----------------------------------------------------
// DATABASE INITIALIZATION
// ----------------------------------------------------

async function initDatabase() {
  console.log("Connecting to PostgreSQL...");

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS lectures (
      id SERIAL PRIMARY KEY,
      module_no INTEGER NOT NULL,
      level TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      video_url TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  databaseReady = true;

  console.log(
    "Database initialized successfully."
  );

  const ownerResult = await pool.query(
    `SELECT id FROM users
     WHERE role='owner'
     LIMIT 1`
  );

  if (ownerResult.rowCount === 0) {
    generateSetupCode();
  } else {
    console.log("Owner account already exists.");
  }
}

// ----------------------------------------------------
// WEBSITE
// ----------------------------------------------------

app.get("/", (req, res) => {
  res.sendFile(indexPath, (error) => {
    if (error) {
      console.error(
        "Could not send index.html:",
        error
      );

      if (!res.headersSent) {
        res.status(500).send(
          "Website file could not be loaded. Check public/index.html."
        );
      }
    }
  });
});

// ----------------------------------------------------
// API 404
// ----------------------------------------------------

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API endpoint not found"
  });
});

// ----------------------------------------------------
// PAGE 404
// ----------------------------------------------------

app.use((req, res) => {
  res.status(404).send(
    "Page not found"
  );
});

// ----------------------------------------------------
// ERROR HANDLER
// ----------------------------------------------------

app.use((error, req, res, next) => {
  console.error(
    "Unhandled server error:",
    error
  );

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "Internal server error"
  });
});

// ----------------------------------------------------
// START SERVER FIRST
// ----------------------------------------------------

async function startServer() {
  const server = app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log(
        `✓ TradeSmart server running on port ${PORT}`
      );

      console.log(
        `✓ Website directory: ${publicPath}`
      );

      console.log(
        "✓ Server test: /server-test"
      );

      console.log(
        "✓ Health check: /health"
      );
    }
  );

  // Initialize Neon AFTER the HTTP server has started.
  try {
    await initDatabase();
  } catch (error) {
    databaseReady = false;

    console.error(
      "DATABASE INITIALIZATION FAILED:"
    );

    console.error(error);

    console.error(
      "The web server is still running, but database features are unavailable."
    );
  }

  const shutdown = async () => {
    console.log(
      "Shutting down server..."
    );

    server.close(async () => {
      await pool.end().catch(() => {});

      process.exit(0);
    });
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

// ----------------------------------------------------
// PROCESS ERROR LOGGING
// ----------------------------------------------------

process.on("uncaughtException", (error) => {
  console.error(
    "UNCAUGHT EXCEPTION:",
    error
  );
});

process.on("unhandledRejection", (error) => {
  console.error(
    "UNHANDLED REJECTION:",
    error
  );
});

startServer();