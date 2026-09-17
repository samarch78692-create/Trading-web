const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT) || 3000;

/* =========================================================
   ENVIRONMENT VARIABLES
========================================================= */

const requiredEnv = [
  "DATABASE_URL",
  "JWT_SECRET",
  "OWNER_EMAIL",
  "OWNER_PASSWORD"
];

for (const name of requiredEnv) {
  if (!process.env[name]) {
    console.error(`ERROR: Missing environment variable: ${name}`);
    process.exit(1);
  }
}

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

pool.on("error", (error) => {
  console.error("Unexpected database pool error:", error);
});

/* =========================================================
   PATHS
========================================================= */

const publicPath = path.join(__dirname, "public");
const indexPath = path.join(publicPath, "index.html");

/* =========================================================
   MIDDLEWARE
========================================================= */

app.disable("x-powered-by");

app.use(express.json({ limit: "1mb" }));

/*
  IMPORTANT:

  GitHub structure MUST be:

  server.js
  package.json
  public/
    index.html

  "public" is lowercase.
*/

app.use(
  express.static(publicPath, {
    index: "index.html",
    maxAge: "1h"
  })
);

/* =========================================================
   AUTHENTICATION
========================================================= */

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Login required"
      });
    }

    const token = header.substring(7);

    req.user = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

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

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.status(200).json({
      ok: true
    });
  } catch (error) {
    console.error("Health check failed:", error);

    res.status(503).json({
      ok: false
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
  try {
    const email = String(
      req.body?.email || ""
    ).toLowerCase().trim();

    const password = String(
      req.body?.password || ""
    );

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
      process.env.JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    return res.json({
      token
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      error: "Server error"
    });
  }
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get("/api/me", auth, (req, res) => {
  res.json({
    user: req.user
  });
});

/* =========================================================
   LECTURES - PUBLIC
========================================================= */

app.get("/api/lectures", async (req, res) => {
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

/* =========================================================
   STUDENTS - OWNER ONLY
========================================================= */

app.get(
  "/api/students",
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

/* =========================================================
   CREATE STUDENT - OWNER ONLY
========================================================= */

app.post(
  "/api/students",
  auth,
  owner,
  async (req, res) => {
    try {
      const email = String(
        req.body?.email || ""
      ).toLowerCase().trim();

      const password = String(
        req.body?.password || ""
      );

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

      const passwordHash = await bcrypt.hash(
        password,
        10
      );

      await pool.query(
        `INSERT INTO users
          (email, password_hash, role)
         VALUES
          ($1, $2, 'student')`,
        [
          email,
          passwordHash
        ]
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

/* =========================================================
   DELETE STUDENT - OWNER ONLY
========================================================= */

app.delete(
  "/api/students/:id",
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

/* =========================================================
   CREATE LECTURE - OWNER ONLY
========================================================= */

app.post(
  "/api/lectures",
  auth,
  owner,
  async (req, res) => {
    try {
      const moduleNo = Number(
        req.body?.module_no
      );

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

      if (
        !Number.isInteger(moduleNo) ||
        moduleNo < 1
      ) {
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

/* =========================================================
   DELETE LECTURE - OWNER ONLY
========================================================= */

app.delete(
  "/api/lectures/:id",
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

/* =========================================================
   MAIN WEBSITE
========================================================= */

/*
  Express static middleware above automatically serves:

  /              -> public/index.html
  /index.html    -> public/index.html
  /anything.css  -> public/anything.css
  /anything.js   -> public/anything.js
  /images/...    -> public/images/...
*/

app.get("/", (req, res) => {
  res.sendFile(indexPath, (error) => {
    if (error) {
      console.error("Could not send index.html:", error);

      if (!res.headersSent) {
        res.status(500).send(
          "Website file could not be loaded. Check that public/index.html exists."
        );
      }
    }
  });
});

/* =========================================================
   API 404
========================================================= */

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API endpoint not found"
  });
});

/* =========================================================
   GENERAL 404
========================================================= */

app.use((req, res) => {
  res.status(404).send("Page not found");
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error("Unhandled server error:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "Internal server error"
  });
});

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initDatabase() {
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

  const ownerEmail =
    process.env.OWNER_EMAIL.toLowerCase().trim();

  const ownerResult = await pool.query(
    "SELECT id FROM users WHERE email=$1",
    [ownerEmail]
  );

  if (ownerResult.rowCount === 0) {
    const passwordHash = await bcrypt.hash(
      process.env.OWNER_PASSWORD,
      10
    );

    await pool.query(
      `INSERT INTO users
        (email, password_hash, role)
       VALUES
        ($1, $2, 'owner')`,
      [
        ownerEmail,
        passwordHash
      ]
    );

    console.log("Owner account created.");
  } else {
    console.log("Owner account already exists.");
  }

  console.log("Database initialized successfully.");
}

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await initDatabase();

    const server = app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `✓ Server running on port ${PORT}`
        );
        console.log(
          `✓ Website directory: ${publicPath}`
        );
        console.log(
          `✓ Health check: /health`
        );
      }
    );

    /* Graceful shutdown */
    const shutdown = async () => {
      console.log("Shutting down server...");

      server.close(async () => {
        await pool.end();
        process.exit(0);
      });
    };

    process.on("SIGTERM", shutdown);
    process.on("SIGINT", shutdown);

  } catch (error) {
    console.error(
      "Failed to start server:",
      error
    );

    await pool.end().catch(() => {});

    process.exit(1);
  }
}

startServer();
