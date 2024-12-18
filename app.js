const express = require("express");
const bodyParser = require("body-parser");
const multer = require("multer");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const app = express();
const port = 3000;

// Environment Variables
const SECRET_KEY = process.env.SECRET_KEY || "SAIRAM";

// Middleware
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// CORS Configuration
const corsOptions = {
  origin: 'https://task-validator-front-en2b3ns3q-sai-ram-s-projects-82f7cf97.vercel.app',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};
app.use(cors(corsOptions));

// Ensure 'uploads' directory exists
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// Database Setup
const db = new sqlite3.Database("tasks.db", (err) => {
  if (err) console.error(err.message);
  else console.log("Connected to SQLite database.");
});

// Create Tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      due_date TEXT NOT NULL,
      creator TEXT NOT NULL,
      assignee TEXT NOT NULL,
      status TEXT DEFAULT 'Pending',
      proof TEXT
    )
  `);
});

// Routes

// Register Route
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
      if (err) {
        return res.status(400).json({ message: "User already exists." });
      }
      res.status(201).json({ message: "User registered successfully." });
    });
  } catch (error) {
    res.status(500).json({ message: "Internal server error." });
  }
});

// Login Route
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err || !user) return res.status(400).json({ message: "Invalid credentials." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials." });

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
    res.status(200).json({ token });
  });
});

// Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized." });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token has expired. Please log in again." });
    }
    res.status(401).json({ message: "Invalid token." });
  }
};

// Create Task
app.post("/tasks", authenticate, (req, res) => {
  const { title, description, due_date, assignee } = req.body;
  const creator = req.user.username;

  db.run(
    "INSERT INTO tasks (title, description, due_date, creator, assignee) VALUES (?, ?, ?, ?, ?)",
    [title, description, due_date, creator, assignee],
    (err) => {
      if (err) {
        res.status(500).json({ message: "Failed to create task." });
      } else {
        res.status(201).json({ message: "Task created successfully." });
      }
    }
  );
});

// Fetch Tasks
app.get("/tasks", authenticate, (req, res) => {
  const username = req.user.username;

  db.all(
    "SELECT * FROM tasks WHERE assignee = ? OR creator = ? AND WHERE status = 'Pending'",
    [username, username],
    (err, rows) => {
      if (err) res.status(500).json({ message: "Failed to fetch tasks." });
      else res.status(200).json(rows);
    }
  );
});

// Submit Proof
app.post("/tasks/:id/proof", authenticate, upload.single("proof"), (req, res) => {
  const taskId = req.params.id;
  const proof = req.file.path;

  db.run("UPDATE tasks SET proof = ? WHERE id = ?", [proof, taskId], (err) => {
    if (err) res.status(500).json({ message: "Failed to submit proof." });
    else res.status(200).json({ message: "Proof submitted successfully." });
  });
});

// Validate Task
app.post("/tasks/:id/validate", authenticate, (req, res) => {
  const taskId = req.params.id;
  const { status } = req.body;

  if (!["Approved", "Rejected"].includes(status)) {
    return res.status(400).json({ message: "Invalid status." });
  }

  db.run("UPDATE tasks SET status = ? WHERE id = ?", [status, taskId], (err) => {
    if (err) res.status(500).json({ message: "Failed to update task status." });
    else res.status(200).json({ message: "Task status updated successfully." });
  });
});

// Fetch Proof
app.get("/tasks/:id/proof", authenticate, (req, res) => {
  const taskId = req.params.id;

  db.get("SELECT proof FROM tasks WHERE id = ?", [taskId], (err, row) => {
    if (err || !row?.proof) return res.status(404).json({ message: "Proof not found." });

    res.status(200).json({ proof: row.proof });
  });
});

// Logout Route
app.post("/logout", (req, res) => {
  res.status(200).json({ message: "Successfully logged out." });
});

// Start Server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
