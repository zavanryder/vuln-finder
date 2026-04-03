/**
 * Vulnerable: Prototype pollution via recursive merge of user input.
 */
function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
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
  const settings = deepMerge(defaults, req.body);
  res.json(settings);
});
