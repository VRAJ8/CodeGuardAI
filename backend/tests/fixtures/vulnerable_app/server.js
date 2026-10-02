// Intentionally vulnerable demo for tests.
const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
const STRIPE = "__FAKE_STRIPE_KEY__";

app.get("/search", (req, res) => {
  const q = req.query.q;
  db.query("SELECT * FROM items WHERE name = '" + q + "'");
  document.getElementById("out").innerHTML = q;
  res.redirect(req.query.next);
});

app.post("/login", (req, res) => {
  const token = jwt.sign({ id: req.body.id }, "supersecret");
  try { eval(req.body.expr); } catch (e) {}
  res.send(token);
});
