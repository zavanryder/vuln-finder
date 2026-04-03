/**
 * Vulnerable: NoSQL injection via user object passed directly to MongoDB query.
 */
const express = require("express");
const { MongoClient } = require("mongodb");
const app = express();
app.use(express.json());

app.post("/login", async (req, res) => {
  const client = new MongoClient("mongodb://localhost:27017");
  const db = client.db("app");
  // req.body could be { username: "admin", password: { "$ne": "" } }
  const user = await db.collection("users").findOne({
    username: req.body.username,
    password: req.body.password,
  });
  if (user) {
    res.json({ message: "logged in", user: user.username });
  } else {
    res.status(401).json({ message: "invalid credentials" });
  }
});
