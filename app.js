const express = require("express");
const bodyParser = require("body-parser");
const multer = require("multer");
const cors = require("cors");
const { Client } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cloudinary = require("cloudinary").v2;
require("dotenv").config();

const app = express();
const port = 3000;



// Define the transporter
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Environment Variables
const SECRET_KEY = process.env.SECRET_KEY || "SAIRAM";

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Middleware
app.use(bodyParser.json());
app.use(cors({
  origin: [
    'https://task-validator-front-end.vercel.app',
    'https://task-validator-front-en2b3ns3q-sai-ram-s-projects-82f7cf97.vercel.app',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// Multer Configuration for Temporary Storage
const storage = multer.memoryStorage(); // Use memory storage to handle uploads before sending to Cloudinary
const upload = multer({ storage });

// PostgreSQL Database Setup
const client = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
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

// User Registration
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

// User Login
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

// Fetch Tasks Created by the User
app.get("/tasks", authenticate, async (req, res) => {
  const username = req.user.username;

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

// Fetch Tasks Assigned to the User
app.get("/tasks/validate", authenticate, async (req, res) => {
  const username = req.user.username;

  try {
    const result = await client.query(
      "SELECT * FROM tasks WHERE assignee = $1 AND status = 'Pending'",
      [username]
    );
    res.status(200).json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch tasks." });
  }
});

// Submit Proof (Upload to Cloudinary)
app.post("/tasks/:id/proof", authenticate, upload.single("proof"), async (req, res) => {
  const taskId = req.params.id;
  const file = req.file;

  if (!file) {
    return res.status(400).json({ message: "No file uploaded." });
  }

  try {
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        { folder: "task_validator_proofs" },
        (error, result) => {
          if (error) {
            return reject(new Error("Cloudinary upload failed."));
          }
          resolve(result);
        }
      );
      uploadStream.end(file.buffer);
    });

    // Update the database with the secure URL of the uploaded image
    await client.query("UPDATE tasks SET proof = $1 WHERE id = $2", [result.secure_url, taskId]);

    res.status(200).json({ message: "Proof submitted successfully.", proofUrl: result.secure_url });
  } catch (err) {
    res.status(500).json({ message: "Failed to submit proof.", error: err.message });
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
    res.status(500).json({ message: "Failed to fetch proof.", error: err.message });
  }
});

// Update Task
app.put("/tasks/:id", authenticate, async (req, res) => {
  const { title, description, due_date, assignee } = req.body;
  const { id } = req.params;

  try {
    const result = await client.query(
      "UPDATE tasks SET title = $1, description = $2, due_date = $3, assignee = $4 WHERE id = $5 RETURNING *",
      [title, description, due_date, assignee, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "Task not found." });
    }

    res.status(200).json({ message: "Task updated successfully.", task: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: "Failed to update task." });
  }
});

// Delete Task
app.delete("/tasks/:id", authenticate, async (req, res) => {
  const taskId = req.params.id;

  try {
    const result = await client.query("DELETE FROM tasks WHERE id = $1 RETURNING *", [taskId]);

    if (!result.rows.length) {
      return res.status(404).json({ message: "Task not found." });
    }

    res.status(200).json({ message: "Task deleted successfully." });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete task." });
  }
});

// Validate Task
app.post("/tasks/:id/validate", authenticate, async (req, res) => {
  const taskId = req.params.id;
  const { status } = req.body;
  const approver = req.user.username;

  if (!["Approved", "Rejected"].includes(status)) {
    return res.status(400).json({ message: "Invalid status." });
  }

  try {
    console.log(`Updating task status for task ID: ${taskId}`);
    await client.query("UPDATE tasks SET status = $1 WHERE id = $2", [status, taskId]);

    if (status === "Approved") {
      console.log(`Fetching task details for task ID: ${taskId}`);
      const result = await client.query(
        "SELECT tasks.creator, tasks.title, users.username, users.email FROM tasks JOIN users ON tasks.creator = users.username WHERE tasks.id = $1",
        [taskId]
      );
      const taskDetails = result.rows[0];
      
      console.log('Task details:', taskDetails);

      if (taskDetails?.email) {
        const emailContent = `
          Hello ${taskDetails.creator},
          
          Your task titled "${taskDetails.title}" has been approved by ${approver}.
          
          Regards,
          Task Validator Team
        `;

        console.log('Sending email to:', taskDetails.email);
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: taskDetails.email,
          subject: "Task Approved Notification",
          text: emailContent,
        });

        console.log('Email sent successfully');
      } else {
        console.log('No email found for task creator');
      }
    }

    res.status(200).json({ message: "Task status updated successfully." });
  } catch (err) {
    console.error('Error occurred:', err);  // Log the error for debugging
    res.status(500).json({ message: "Failed to update task status." });
  }
});


// Logout
app.post("/logout", (req, res) => {
  res.status(200).json({ message: "Successfully logged out." });
});

// Start Server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
