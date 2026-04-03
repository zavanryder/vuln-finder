/**
 * Vulnerable: Command injection via child_process.exec with user input.
 */
const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    res.send(`<pre>${stdout}</pre>`);
  });
});

app.get("/lookup", (req, res) => {
  const domain = req.query.domain;
  exec("nslookup " + domain, (error, stdout) => {
    res.json({ result: stdout });
  });
});
