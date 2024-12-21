const express = require("express");
const bodyParser = require("body-parser");
const multer = require("multer");
const cors = require("cors");
const { Client } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const nodemailer = require("nodemailer");
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
  origin: [
    'https://task-validator-front-end.vercel.app',
    'https://task-validator-front-en2b3ns3q-sai-ram-s-projects-82f7cf97.vercel.app'
  ],
  methods: ['GET', 'POST','PUT'],
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

// PostgreSQL Database Setup
const client = new Client({
  connectionString: process.env.DATABASE_URL, // Connection string from Neon or your PostgreSQL service
  ssl: {
    rejectUnauthorized: false, // For SSL connections, set this to false if needed
  }
});

client.connect((err) => {
  if (err) console.error('Connection error', err.stack);
  else console.log('Connected to PostgreSQL database');
});

// Create Tables
const createTables = async () => {
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS tasks (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        due_date TEXT NOT NULL,
        creator TEXT NOT NULL,
        assignee TEXT NOT NULL,
        status TEXT DEFAULT 'Pending',
        proof TEXT
      )
    `);
  } catch (error) {
    console.error("Error creating tables: ", error);
  }
};

createTables();

// Nodemailer Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Routes

// Register Route
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await client.query("INSERT INTO users (username, password) VALUES ($1, $2)", [username, hashedPassword]);
    res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    res.status(400).json({ message: "User already exists." });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await client.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ message: "Invalid credentials." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials." });

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ message: "Internal server error." });
  }
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
app.post("/tasks", authenticate, async (req, res) => {
  const { title, description, due_date, assignee } = req.body;
  const creator = req.user.username;

  try {
    await client.query(
      "INSERT INTO tasks (title, description, due_date, creator, assignee) VALUES ($1, $2, $3, $4, $5)",
      [title, description, due_date, creator, assignee]
    );
    res.status(201).json({ message: "Task created successfully." });
  } catch (err) {
    res.status(500).json({ message: "Failed to create task." });
  }
});


app.get("/tasks", authenticate, async (req, res) => {
  const username = req.user.username; // The authenticated user's username

  try {
    const result = await client.query(
      "SELECT * FROM tasks WHERE creator = $1 AND status = 'Pending'",
      [username]
    );
    res.status(200).json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch created tasks." });
  }
});


// Fetch Tasks
// app.get("/tasks", authenticate, async (req, res) => {
//   const username = req.user.username;  // The authenticated user's username
//   const otheruser = req.query.creator; // The query parameter 'creator' (or 'otheruser')

//   const userToFetch = otheruser || username;

//   try {
//     const result = await client.query(
//       "SELECT * FROM tasks WHERE assignee = $1 OR creator = $1 AND status = 'Pending'",
//       [userToFetch]
//     );
//     res.status(200).json(result.rows);
//   } catch (err) {
//     res.status(500).json({ message: "Failed to fetch tasks." });
//   }
// });


app.get("/tasks/validate", authenticate, async (req, res) => {
  const username = req.user.username; // The authenticated user's username from the token

  try {
    const result = await client.query(
      "SELECT * FROM tasks WHERE assignee = $1 AND status = 'Pending'",
      [username]
    );
    res.status(200).json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch tasks.", error: err.message });
  }
});


// Submit Proof
app.post("/tasks/:id/proof", authenticate, upload.single("proof"), async (req, res) => {
  const taskId = req.params.id;
  const proof = req.file.path;

  try {
    await client.query("UPDATE tasks SET proof = $1 WHERE id = $2", [proof, taskId]);
    res.status(200).json({ message: "Proof submitted successfully." });
  } catch (err) {
    res.status(500).json({ message: "Failed to submit proof." });
  }
});

// Validate Task
// Validate Task
app.post("/tasks/:id/validate", authenticate, async (req, res) => {
  const taskId = req.params.id;
  const { status } = req.body;
  const approver = req.user.username; // Fetch the username of the person approving the task

  if (!["Approved", "Rejected"].includes(status)) {
    return res.status(400).json({ message: "Invalid status." });
  }

  try {
    // Update the task status
    await client.query("UPDATE tasks SET status = $1 WHERE id = $2", [status, taskId]);

    if (status === "Approved") {
      // Fetch creator email and task details
      const result = await client.query(
        "SELECT tasks.creator, tasks.title, users.username, users.email FROM tasks JOIN users ON tasks.creator = users.username WHERE tasks.id = $1",
        [taskId]
      );
      const taskDetails = result.rows[0];

      if (taskDetails?.email) {
        // Send email notification
        const emailContent = `
          Hello ${taskDetails.creator},
          
          Your task titled "${taskDetails.title}" has been approved by ${approver}.
          
          Thanks for using Task Validator! Start validating your tasks and stay on track with Task Validator! Boost your performance with our accurate and efficient task checker.

          Regards,
          Task Validator Team
        `;

        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: taskDetails.email,
          subject: "Task Approved Notification",
          text: emailContent,
        });
      }
    }

    res.status(200).json({ message: "Task status updated successfully." });
  } catch (err) {
    res.status(500).json({ message: "Failed to update task status." });
  }
});


// Fetch Proof
app.get("/tasks/:id/proof", authenticate, async (req, res) => {
  const taskId = req.params.id;

  try {
    const result = await client.query("SELECT proof FROM tasks WHERE id = $1", [taskId]);
    if (!result.rows.length || !result.rows[0].proof) {
      return res.status(404).json({ message: "Proof not found." });
    }
    res.status(200).json({ proof: result.rows[0].proof });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch proof." });
  }
});


// Import necessary modules
app.put("/tasks/:id", authenticate, async (req, res) => {
  const { title, description, due_date, assignee } = req.body;
  const { id } = req.params; // Get the task ID from the URL parameters

  try {
    // Query to update the task details in the database
    const result = await client.query(
      "UPDATE tasks SET title = $1, description = $2, due_date = $3, assignee = $4 WHERE id = $5 RETURNING *",
      [title, description, due_date, assignee, id]
    );

    // Check if a task was updated
    if (result.rowCount === 0) {
      return res.status(404).json({ message: "Task not found." });
    }

    // Send the updated task as a response
    res.status(200).json({ message: "Task updated successfully.", task: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to update task." });
  }
});


// Logout Route
app.post("/logout", (req, res) => {
  res.status(200).json({ message: "Successfully logged out." });
});

// Start Server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
