/**
 * Safe: Merge skips __proto__ and constructor keys.
 */
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

const express = require("express");
const app = express();
app.use(express.json());

app.post("/config", (req, res) => {
  const defaults = { theme: "light", lang: "en" };
  const settings = safeMerge(defaults, req.body);
  res.json(settings);
});
