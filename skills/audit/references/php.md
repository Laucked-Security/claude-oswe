# PHP / Laravel / Symfony — Source→Sink Reference

## Sources (attacker-controllable)
- Superglobals: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER` (headers like
  `HTTP_*`, `PHP_AUTH_*`), `php://input`, `getallheaders()`.
- Laravel: `$request->input()`, `$request->all()`, `$request->query()`, route params, `request()`.
- Symfony: `$request->request->get()`, `$request->query->get()`, `$request->headers->get()`.

## Dangerous sinks by class
- **SQLi**: `mysqli_query`, `$pdo->query`, raw `DB::raw`, `DB::select` with string concat,
  Eloquent `whereRaw`, Doctrine raw DQL/SQL with concatenation.
- **Command injection**: `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, `popen`,
  backticks `` `...` ``, `pcntl_exec`.
- **Code/eval**: `eval`, `assert` (string arg), `create_function`, `call_user_func(_array)` with
  attacker-chosen callable, `preg_replace` with `/e` (legacy).
- **PHP object injection / POP chains**: `unserialize()` on attacker data; look for magic methods
  `__wakeup`, `__destruct`, `__toString`, `__call` in reachable classes (and in `vendor/` for
  known gadget chains — read on demand). Laravel: `decrypt()`/`unserialize` mis-use.
- **LFI/RFI / path traversal**: `include`, `require`, `include_once`, `require_once`, `fopen`,
  `file_get_contents`, `readfile`, `file()` with attacker path; `allow_url_include`.
- **File upload → RCE**: `move_uploaded_file` / `file_put_contents` writing attacker-named or
  attacker-typed files into a web-served directory without extension/content validation.
- **SSRF**: `curl_exec`, `file_get_contents` / `fopen` on attacker URL, `GuzzleHttp` with attacker host.
- **XXE**: `simplexml_load_string`, `DOMDocument->loadXML` with `LIBXML_NOENT` / external entities enabled.

## Type juggling (classic OSWE)
- Loose comparison `==` / `!=` and `in_array($x, $arr)` (loose) on attacker input.
- **Magic hashes**: `md5`/`sha1` digests of the form `0e\d+` compare equal under `==` (e.g.
  `md5("240610708") == "0e..."`). Auth checks like `if (md5($pw) == $stored)` are bypassable.
- `strcmp($a, $b)` returning `NULL` (PHP < 8) when passed an array → `== 0` bypass.
- Fix indicators (safe): `===`, `hash_equals()`, `password_verify()`.

## Framework auth boundaries
- Laravel: `auth` middleware, `@can`, policies, `$this->authorize()`. Missing middleware on a route
  = unauthenticated reachability.
- Symfony: `#[IsGranted]`, firewall config in `security.yaml`, voters.

## Sanitizers and why they often fail
- `addslashes`/manual escaping vs parameterized queries (insufficient against many encodings).
- `htmlspecialchars` is output-encoding (XSS) — irrelevant to SQLi/RCE sinks.
- `basename()` does not stop all traversal when extension/path is attacker-influenced downstream.
