/**
 * Chain fixture: IDOR + path traversal -> read secrets -> forge auth.
 *
 * Expected chain:
 * 1. /api/users/:id has no authorization check (IDOR / object-level-authz)
 * 2. /files endpoint has path traversal
 * 3. Attacker reads .env via path traversal to get JWT_SECRET
 * 4. Attacker forges JWT to access any user's data via IDOR
 */
const express = require("express");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "hardcoded-fallback-secret";

// Auth middleware -- verifies JWT but does NOT check user owns the resource
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "no token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
}

// IDOR: any authenticated user can access any user by ID
app.get("/api/users/:id", auth, (req, res) => {
  const userId = req.params.id;
  // No check that req.user.sub === userId
  const user = { id: userId, email: `user${userId}@example.com`, ssn: "123-45-6789" };
  res.json(user);
});

// Path traversal: insufficient sanitization
app.get("/files", (req, res) => {
  const name = req.query.name;
  const filePath = path.join(__dirname, "uploads", name);
  if (!fs.existsSync(filePath)) return res.status(404).send("not found");
  res.sendFile(filePath);
});

app.listen(3000);
