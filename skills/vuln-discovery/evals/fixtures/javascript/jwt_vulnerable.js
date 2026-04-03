/**
 * Vulnerable: JWT issues -- no algorithm pinning, weak secret, decode without verify.
 */
const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();

const SECRET = "secret";

app.get("/profile", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  // No algorithm restriction -- accepts alg=none
  const decoded = jwt.verify(token, SECRET);
  res.json({ user: decoded.sub });
});

app.get("/public-profile", (req, res) => {
  const token = req.query.token;
  // decode without verification -- anyone can forge
  const decoded = jwt.decode(token);
  res.json({ user: decoded.sub, email: decoded.email });
});
