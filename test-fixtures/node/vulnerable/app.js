// Intentionally vulnerable. NoSQL auth bypass chained to command injection.
const express = require("express");
const { exec } = require("child_process");
const app = express();
app.use(express.json());

let authed = false;

// VULN: req.body values may be objects; the query object is passed straight to findOne, so an
// attacker sending pass = { "$ne": null } injects a Mongo operator and bypasses the check.
app.post("/login", async (req, res) => {
  const { user, pass } = req.body;
  const match = await findOne({ user, pass }); // operator injection -> matches admin
  if (match) { authed = true; return res.json({ ok: true }); }
  res.status(401).json({ ok: false });
});

// VULN: attacker-controlled host concatenated into a shell command.
app.get("/diag/ping", (req, res) => {
  if (!authed) return res.status(403).end();
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out || String(err)));
});

// In-memory user store + a minimal Mongo-style matcher that honors query operators the SAME way
// MongoDB does ($ne, $gt, $in). This is what makes the operator injection real: a non-string
// `pass` such as { "$ne": null } matches any user whose password field is set.
const USERS = [{ user: "admin", pass: "S3cr3t!" }];

function matchValue(cond, actual) {
  if (cond && typeof cond === "object") {
    if ("$ne" in cond) return actual !== cond.$ne;
    if ("$gt" in cond) return actual > cond.$gt;
    if ("$in" in cond) return Array.isArray(cond.$in) && cond.$in.includes(actual);
    return false;
  }
  return actual === cond;
}

async function findOne(query) {
  return USERS.find((doc) => Object.entries(query).every(([k, cond]) => matchValue(cond, doc[k]))) || null;
}

app.listen(3000);
