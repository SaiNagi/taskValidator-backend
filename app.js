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
app.post("/register", upload.single("image"), async (req, res) => {
  const { username, password, email } = req.body;
  const file = req.file;

  if (!file) {
    return res.status(400).json({ message: "No image uploaded." });
  }

  try {
    // Upload the image to Cloudinary
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        { folder: "task_validator_users" }, // Cloudinary folder name
        (error, result) => {
          if (error) {
            return reject(new Error("Cloudinary upload failed."));
          }
          resolve(result);
        }
      );
      uploadStream.end(file.buffer);
    });

    const hashedPassword = await bcrypt.hash(password, 10);
    const imageUrl = result.secure_url; // Get the uploaded image URL

    // Insert the user data into the database
    await client.query(
      "INSERT INTO users (username, password, email, image) VALUES ($1, $2, $3, $4)",
      [username, hashedPassword, email, imageUrl]
    );

    res.status(201).json({ message: "User registered successfully.", imageUrl });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Registration failed.", error: error.message });
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

    // Fetch task details to notify the creator
    const taskDetailsQuery = `
      SELECT tasks.creator, tasks.title, users.email 
      FROM tasks 
      JOIN users ON tasks.creator = users.username 
      WHERE tasks.id = $1
    `;
    const taskResult = await client.query(taskDetailsQuery, [taskId]);
    const taskDetails = taskResult.rows[0];

    if (taskDetails?.email) {
      const emailHtmlContent = `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; padding: 20px;">
          <h2 style="color: #4CAF50;">Task Proof Submitted - Action Required</h2>
          <p>Hello <strong>${taskDetails.creator}</strong>,</p>
          <p>A proof has been submitted for the task titled 
            <strong style="color: #4CAF50;">"${taskDetails.title}"</strong>.
            Your immediate attention is needed to validate this task.
          </p>
          <p style="margin-top: 10px;">
            Please log in and validate the task carefully, as your decision will help maintain consistency.
          </p>
          <div style="text-align: center; margin: 20px 0;">
            <a href="https://task-validator-front-end.vercel.app/login" 
               style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 16px;">
              Login to Validate Task
            </a>
          </div>
          <p>If the above button doesn't work, you can copy and paste this link into your browser:</p>
          <p style="color: #007BFF;">https://task-validator-front-end.vercel.app/login</p>
          <p style="margin-top: 20px; color: #777;">Thank you for helping us maintain task validation standards!</p>
          <p style="font-size: 14px; color: #999;">Regards, <br>Task Validator Team</p>
        </div>
      `;

      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: taskDetails.email,
        subject: "Task Proof Submitted - Action Required",
        html: emailHtmlContent,
      });
    }

    res.status(200).json({ message: "Proof submitted successfully.", proofUrl: result.secure_url });
  } catch (err) {
    console.error("Error occurred:", err);
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
    console.log(`Validating task ID: ${taskId}`);
    
    // Fetch task details
    const taskResult = await client.query(
      "SELECT tasks.creator, tasks.title, tasks.due_date, tasks.status, users.username, users.email, users.score FROM tasks JOIN users ON tasks.creator = users.username WHERE tasks.id = $1",
      [taskId]
    );
    const taskDetails = taskResult.rows[0];

    if (!taskDetails) {
      return res.status(404).json({ message: "Task not found." });
    }

    console.log("Task details:", taskDetails);

    let newScore = taskDetails.score; // Initialize with current score

    if (status === "Approved") {
      const currentDate = new Date();
      const dueDate = new Date(taskDetails.due_date);

      // Determine score to add based on due date
      const scoreToAdd = currentDate <= dueDate ? 10 : 5;
      newScore += scoreToAdd;

      // Update task status and user score
      await client.query("UPDATE tasks SET status = $1 WHERE id = $2", ["Approved", taskId]);
      await client.query("UPDATE users SET score = $1 WHERE username = $2", [newScore, taskDetails.creator]);

      // Send approval email
      if (taskDetails.email) {
        const emailContent = `
          Hello ${taskDetails.creator},
          
          Your task titled "${taskDetails.title}" has been approved by ${approver}.
          You have earned ${scoreToAdd} points. Your updated score is now ${newScore}.
          
          Regards,
          Task Validator Team
        `;

        console.log("Sending approval email to:", taskDetails.email);
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: taskDetails.email,
          subject: "Task Approved Notification",
          text: emailContent,
        });
        console.log("Approval email sent successfully.");
      }
    } else if (status === "Rejected") {
      const scoreToDeduct = 3;
      newScore -= scoreToDeduct;

      // Update user score and keep the task status as "Pending"
      await client.query("UPDATE users SET score = $1 WHERE username = $2", [newScore, taskDetails.creator]);
      await client.query("UPDATE tasks SET status = $1 WHERE id = $2", ["Pending", taskId]);

      // Send rejection email
      if (taskDetails.email) {
        const emailContent = `
          Hello ${taskDetails.creator},
          
          Your task titled "${taskDetails.title}" has been rejected by ${approver}.
          Please resubmit the proof for this task. Your score has been reduced by ${scoreToDeduct} points.
          Your updated score is now ${newScore}.
          
          Regards,
          Task Validator Team
        `;

        console.log("Sending rejection email to:", taskDetails.email);
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: taskDetails.email,
          subject: "Task Rejected Notification",
          text: emailContent,
        });
        console.log("Rejection email sent successfully.");
      }
    }

    res.status(200).json({ message: "Task validation processed successfully." });
  } catch (err) {
    console.error("Error occurred:", err); // Log the error for debugging
    res.status(500).json({ message: "Failed to process task validation." });
  }
});


app.get("/user", authenticate, async (req, res) => {
  const userName = req.user.username; // Assume `authenticate` middleware sets `req.user`.

  try {
    const result = await client.query(
      "SELECT username, email, image, score FROM users WHERE  username= $1",
      [userName]
    );

    if (!result.rows.length) {
      return res.status(404).json({ message: "User not found." });
    }

    res.status(200).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch user details.", error: err.message });
  }
});

app.get("/leaderboard", authenticate, async (req, res) => {
  try {
    // Query to fetch leaderboard data
    const result = await client.query(
      `SELECT username, email, score, image 
       FROM users 
       ORDER BY score DESC`
    );

    if (!result.rows.length) {
      return res.status(404).json({ message: "Leaderboard is empty." });
    }

    // Return leaderboard data
    res.status(200).json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch leaderboard data.", error: err.message });
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
