const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Validate environment variables
if (
  !process.env.DATABASE_URL ||
  !process.env.JWT_SECRET ||
  !process.env.OWNER_EMAIL ||
  !process.env.OWNER_PASSWORD
) {
  console.error(
    "ERROR: Missing required environment variables: DATABASE_URL, JWT_SECRET, OWNER_EMAIL, OWNER_PASSWORD"
  );
  process.exit(1);
}

// Database connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Initialize database
async function init() {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create lectures table
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

    // Create owner account if it doesn't exist
    const ownerExists = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [process.env.OWNER_EMAIL]
    );

    if (ownerExists.rowCount === 0) {
      const ownerPasswordHash = await bcrypt.hash(
        process.env.OWNER_PASSWORD,
        10
      );

      await pool.query(
        "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)",
        [process.env.OWNER_EMAIL, ownerPasswordHash, "owner"]
      );

      console.log("✓ Owner account created");
    }
  } catch (error) {
    console.error("Database initialization error:", error);
    throw error;
  }
}

// Authentication middleware
function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Login required" });
    }

    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (error) {
    res.status(401).json({ error: "Login required" });
  }
}

// Owner-only middleware
function owner(req, res, next) {
  if (!req.user || req.user.role !== "owner") {
    return res.status(403).json({ error: "Owner only" });
  }

  next();
}

// Health check
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (error) {
    res.status(503).json({ ok: false });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").toLowerCase().trim();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password required"
      });
    }

    const query = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (query.rowCount === 0) {
      return res.status(401).json({
        error: "Invalid credentials"
      });
    }

    const user = query.rows[0];

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

    res.json({ token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      error: "Server error"
    });
  }
});

// Current user
app.get("/api/me", auth, (req, res) => {
  res.json({
    user: req.user
  });
});

// Get lectures
app.get("/api/lectures", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM lectures ORDER BY module_no, id"
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

// Get students - owner only
app.get("/api/students", auth, owner, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, created_at FROM users WHERE role='student' ORDER BY id DESC"
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
});

// Create student - owner only
app.post("/api/students", auth, owner, async (req, res) => {
  try {
    const email = String(req.body.email || "").toLowerCase().trim();
    const password = String(req.body.password || "");

    if (!email || password.length < 6) {
      return res.status(400).json({
        error: "Valid email and password (min 6 chars) required"
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)",
      [email, passwordHash, "student"]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error("Student creation error:", error);

    if (error.message.includes("duplicate")) {
      return res.status(400).json({
        error: "Email already exists"
      });
    }

    res.status(500).json({
      error: "Server error"
    });
  }
});

// Delete student - owner only
app.delete("/api/students/:id", auth, owner, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM users WHERE id=$1 AND role='student'",
      [req.params.id]
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
});

// Add lecture - owner only
app.post("/api/lectures", auth, owner, async (req, res) => {
  try {
    const moduleNo = Number(req.body.module_no);
    const level = String(req.body.level || "").trim();
    const title = String(req.body.title || "").trim();
    const description = String(req.body.description || "").trim();
    const videoUrl = String(req.body.video_url || "").trim();

    if (
      !Number.isInteger(moduleNo) ||
      moduleNo < 1 ||
      !level ||
      !title
    ) {
      return res.status(400).json({
        error: "Module number, level, and title required"
      });
    }

    await pool.query(
      "INSERT INTO lectures (module_no, level, title, description, video_url) VALUES ($1, $2, $3, $4, $5)",
      [moduleNo, level, title, description, videoUrl]
    );

    res.json({
      ok: true
    });
  } catch (error) {
    console.error("Lecture creation error:", error);

    res.status(500).json({
      error: "Server error"
    });
  }
});

// Delete lecture - owner only
app.delete("/api/lectures/:id", auth, owner, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM lectures WHERE id=$1",
      [req.params.id]
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
});

// Serve index.html for the website
app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

// Fallback for SPA routes
app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

// Start server
init()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`✓ Server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
  });