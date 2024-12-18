// app.js (Backend)
const express = require("express");
const bodyParser = require("body-parser");
const multer = require("multer");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");  // Added fs to handle file system operations
const path = require("path");  // Added path to manage file paths

const app = express();
const port = 3000;

require('dotenv').config();
const SECRET_KEY = "SAIRAM";

// Middleware
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configure CORS options
const corsOptions = {
  origin: ['http://localhost:3001', 'https://task-validator-front-end.vercel.app'], // Allow both localhost and Vercel URLs
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'], // Allow the necessary headers
  credentials: true, // Allow cookies and credentials to be sent
};

// Use CORS middleware with custom options
app.use(cors(corsOptions));

// Ensure 'uploads' directory exists, create it if not
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log("'uploads' directory created.");
}

// Configure multer to handle file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir); // Specify the directory for storing files
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // File name with timestamp
  },
});

const upload = multer({ storage: storage });

// Database setup
const db = new sqlite3.Database("tasks.db", (err) => {
  if (err) console.error(err.message);
  else console.log("Connected to SQLite database.");
});

// Create tables
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )`
  );

  db.run(
    `CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      due_date TEXT NOT NULL,
      creator TEXT NOT NULL,
      assignee TEXT NOT NULL,
      status TEXT DEFAULT 'Pending',
      proof TEXT
    )`
  );
});

// Register route
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

// Login route
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  console.log("Into Login API");
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err || !user) {
      return res.status(400).json({ message: "Invalid credentials." });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials." });
    }
    console.log("Key Used While Logging in :", "SECRET_KEY");
    const token = jwt.sign({ username }, "SECRET_KEY", { expiresIn: "1h", algorithm: 'HS256' });
    console.log("token length: ", token.length);
    console.log("Token generated from the back end : ", token);
    
    res.status(200).json({ token });
  });
});

// Middleware to authenticate requests
const authenticate = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized." });
  console.log("Authentication Token: ", token);
  
  try {
    const decoded = jwt.verify(token, 'SECRET_KEY', { algorithms: ['HS256'] });
    req.user = decoded;
    console.log("Successfully validated at Backend");
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: "Token has expired. Please log in again." });
    }
    res.status(401).json({ message: "Invalid token." });
    console.log("Error during token verification:", error);
  }
};

// Create task
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

// Fetch tasks
app.get("/tasks", authenticate, (req, res) => {
  const username = req.user.username;  // The authenticated user's username
  const otheruser = req.query.creator; // The query parameter 'creator' (or 'otheruser')

  // If 'otheruser' query parameter exists, fetch tasks for 'otheruser', otherwise for the authenticated user
  const userToFetch = otheruser || username;

  console.log("Fetching tasks for: ", userToFetch); // Log the user whose tasks are being fetched

  db.all(
    "SELECT * FROM tasks WHERE assignee = ? OR creator = ? AND status = 'Pending'",
    [userToFetch, userToFetch], // Use the username from the query parameter or the authenticated user
    (err, rows) => {
      if (err) {
        res.status(500).json({ message: "Failed to fetch tasks." });
      } else {
        res.status(200).json(rows);
      }
    }
  );
});

// Submit proof
app.post("/tasks/:id/proof", authenticate, upload.single("proof"), (req, res) => {
  const taskId = req.params.id;
  const proof = req.file.path;
  db.run("UPDATE tasks SET proof = ? WHERE id = ?", [proof, taskId], (err) => {
    if (err) {
      res.status(500).json({ message: "Failed to submit proof." });
    } else {
      res.status(200).json({ message: "Proof submitted successfully." });
    }
  });
});

// Validate task
app.post("/tasks/:id/validate", authenticate, (req, res) => {
  const taskId = req.params.id;
  const { status } = req.body;
  if (!["Approved", "Rejected"].includes(status)) {
    return res.status(400).json({ message: "Invalid status." });
  }
  db.run("UPDATE tasks SET status = ? WHERE id = ?", [status, taskId], (err) => {
    if (err) {
      res.status(500).json({ message: "Failed to update task status." });
    } else {
      res.status(200).json({ message: "Task status updated successfully." });
    }
  });
});

// Fetch task proof
app.get("/tasks/:id/proof", authenticate, (req, res) => {
  const taskId = req.params.id;

  // Fetch the task from the database to get the proof
  db.get("SELECT proof FROM tasks WHERE id = ?", [taskId], (err, row) => {
    if (err) {
      return res.status(500).json({ message: "Failed to fetch task proof." });
    }

    if (!row || !row.proof) {
      return res.status(404).json({ message: "No proof submitted for this task." });
    }

    // Send back the file path or URL
    console.log("URL: ", row);
    console.log("url: ", row.proof);
    res.status(200).json({ proof: row.proof });
  });
});

app.post("/logout", (req, res) => {
  // Clear the token cookie, if it exists
  res.clearCookie("token", { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

  // Respond with a success message
  res.status(200).json({ message: "Successfully logged out" });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
