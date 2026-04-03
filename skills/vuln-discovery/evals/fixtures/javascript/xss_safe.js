/**
 * Safe: XSS -- output is properly escaped / uses textContent.
 */
const express = require("express");
const app = express();

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

app.get("/search", (req, res) => {
  const query = escapeHtml(req.query.q || "");
  res.send(`<h1>Results for: ${query}</h1>`);
});

// Client-side safe pattern
function showMessage(msg) {
  document.getElementById("output").textContent = msg;
}
