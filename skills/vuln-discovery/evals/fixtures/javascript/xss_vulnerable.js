/**
 * Vulnerable: DOM XSS via innerHTML and reflected XSS via unescaped output.
 */
const express = require("express");
const app = express();

// Server-side reflected XSS
app.get("/search", (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Results for: ${query}</h1>`);
});

// Client-side DOM XSS pattern (would be in browser JS)
function showMessage(msg) {
  document.getElementById("output").innerHTML = msg;
}

function showError(error) {
  document.write("<div class='error'>" + error + "</div>");
}
