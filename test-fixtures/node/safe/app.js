// Hardened negative fixture.
const express = require("express");
const { execFile } = require("child_process");
const app = express();
app.use(express.json());

let authed = false;

app.post("/login", (req, res) => {
  // Safe: coerce to strings so query operators cannot be injected.
  const user = String(req.body.user ?? "");
  const pass = String(req.body.pass ?? "");
  if (user === "admin" && pass === "letmein") { authed = true; return res.json({ ok: true }); }
  res.status(401).json({ ok: false });
});

app.get("/diag/ping", (req, res) => {
  if (!authed) return res.status(403).end();
  const host = String(req.query.host ?? "");
  // Safe: strict allow-list + execFile with an argument array (no shell).
  if (!/^[a-z0-9.-]+$/i.test(host)) return res.status(400).end();
  execFile("ping", ["-c", "1", host], (err, out) => res.send(out || String(err)));
});

app.listen(3000);
