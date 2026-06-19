# Node.js / Express / Nest — Source→Sink Reference

## Sources (attacker-controllable)
- Express: `req.query`, `req.body`, `req.params`, `req.headers`, `req.cookies`, `req.files`
  (multer). **Note:** `req.body`/`req.query` values can be **objects/arrays**, not just strings
  (body-parser, `qs`) — central to NoSQL injection and prototype pollution.
- Nest: `@Query()`, `@Body()`, `@Param()`, `@Headers()`, `@Req()`.

## Dangerous sinks by class
- **Command injection**: `child_process.exec`, `execSync`, `spawn`/`execFile` with `shell:true`,
  template strings into a shell. Safe form: `execFile(cmd, [args], {shell:false})`.
- **Code eval**: `eval`, `new Function`, `vm.runInNewContext` with attacker code,
  `setTimeout`/`setInterval` with string arg.
- **NoSQL injection**: MongoDB queries built from `req.body`/`req.query` objects, e.g.
  `User.findOne({ user: req.body.user, pass: req.body.pass })` → `{ "$ne": null }` /
  `{ "$gt": "" }` operator injection bypasses auth. Also `$where` with attacker string.
- **SQLi**: `connection.query("... " + input)`, knex `.raw` with concat, Sequelize `literal()`.
- **Prototype pollution**: recursive merge/clone/`_.set`/`Object.assign` over attacker JSON with
  `__proto__`/`constructor.prototype` keys; gadget → RCE via downstream `child_process` options,
  template engines, or config.
- **Deserialization**: `node-serialize.unserialize`, `serialize-javascript` misuse, `funcster`,
  YAML `load` (non-safe).
- **Path traversal / LFI**: `fs.readFile`/`createReadStream`/`res.sendFile` with attacker path;
  `path.join(root, req.params.x)` without normalization + `..` containment check.
- **SSRF**: `http(s).request`, `axios`, `node-fetch`, `got` to an attacker-controlled URL/host.
- **Template injection (SSTI)**: user input into template source for `ejs`, `pug`, `handlebars`
  compile, `lodash.template`.

## Framework auth boundaries
- Express: auth middleware applied per-route or per-router. A route registered before/without the
  auth middleware is unauthenticated. Check `app.use(auth)` ordering vs route definitions.
- Nest: `@UseGuards(AuthGuard)`; a controller/handler without a guard is unauthenticated.

## Sanitizers and why they often fail
- Casting with `String(x)` neutralizes NoSQL operator injection — its **absence** is the smell.
- `express-mongo-sanitize` strips `$`/`.` keys; if not applied to a given route, operators pass.
- Allow-list extension checks that run on `req.files[].originalname` but then write with the same
  attacker name into a served dir → still RCE.

```surface
{
  "sources": ["req.query", "req.body", "req.params", "req.headers", "req.cookies", "req.files", "@Query(", "@Body(", "@Param(", "@Headers(", "@Req("],
  "sinks": ["child_process.exec", "execSync", ".spawn(", "execFile", "eval(", "new Function", "vm.runInNewContext", "$where", "$ne", "$gt", "$regex", "child_process", "require(", ".query(", "sequelize.query", "res.sendFile"],
  "sanitizers": ["mongo-sanitize", "escape("],
  "auth_markers": ["passport.authenticate", "@UseGuards", "ensureAuthenticated", "req.isAuthenticated(", "requireAuth", "@Roles("]
}
```