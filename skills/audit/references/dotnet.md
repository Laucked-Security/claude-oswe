# .NET / ASP.NET — Source→Sink Reference

## Sources (attacker-controllable)
- ASP.NET Core: `Request.Query`, `Request.Form`, `Request.Body`, `Request.Cookies`, `Request.Headers`,
  `Request.RouteValues`, `[FromBody]` / `[FromQuery]` / `[FromForm]` model binding.
- Classic ASP.NET: `Request.QueryString`, `Request.Form`, `Request.Params`, `Request.Cookies`.

## Dangerous sinks by class
- **Insecure deserialization → RCE**: `BinaryFormatter.Deserialize`, `NetDataContractSerializer`,
  `LosFormatter`, `ObjectStateFormatter`, `Json.NET` with `TypeNameHandling.All/Auto/Objects`,
  `JavaScriptSerializer` with a custom `SimpleTypeResolver`, `fastJSON`. Attacker-chosen type +
  gadget → RCE; read dependencies on demand to confirm a gadget.
- **Command injection**: `Process.Start` / `ProcessStartInfo` with a built shell string
  (`/bin/sh -c "..."` or `cmd /c "..."` with concatenation), `UseShellExecute = true` + arguments
  from input. Safe form: `ArgumentList` with `UseShellExecute = false`, no shell.
- **SQLi**: string-concatenated `SqlCommand` / `SqlDataAdapter`, EF `FromSqlRaw` /
  `ExecuteSqlRaw` with interpolation.
- **XXE**: `XmlDocument` / `XmlReader` / `XmlTextReader` with `DtdProcessing.Parse` and a non-null
  `XmlResolver`. Safe form: `DtdProcessing.Prohibit` and `XmlResolver = null`.
- **SSRF**: `HttpClient`, `WebRequest.Create`, `WebClient` to an attacker URL/host.
- **Path traversal**: `File.ReadAllText` / `Path.Combine(root, input)` without `..` containment.

## Auth boundaries (ASP.NET)
- `[Authorize]` attributes, authorization middleware/policies, `User.IsInRole`. A route without
  `[Authorize]`/policy is unauthenticated-reachable.
- **Trusting raw client cookies/claims** for identity (e.g. `Request.Cookies["admin"] == "1"`,
  an unsigned role claim) is an auth bypass — cookies are client-controllable unless signed/encrypted
  (Data Protection / authentication cookie).

## Sanitizers and why they often fail
- HTML encoding (`HtmlEncoder`) is output encoding (XSS) — irrelevant to deserialization/exec sinks.
- Parameterized `SqlParameter` is the SQLi fix; concatenation/interpolation is the smell.
- `TypeNameHandling.None` (the default in modern Json.NET) is required; `All`/`Auto` reintroduces the
  gadget surface.

```surface
{
  "sources": ["Request.Query", "Request.Form", "Request.Body", "Request.Cookies", "Request.Headers", "Request.RouteValues", "Request.QueryString", "Request.Params", "[FromBody]", "[FromQuery]", "[FromForm]", "[FromRoute]"],
  "sinks": ["BinaryFormatter", "NetDataContractSerializer", "LosFormatter", "ObjectStateFormatter", "TypeNameHandling", "JavaScriptSerializer", "Process.Start", "ProcessStartInfo", "UseShellExecute", "SqlCommand", "ExecuteReader", "ExecuteNonQuery", "FromSqlRaw", "ExecuteSqlRaw", "XmlDocument", "XmlReader", "Path.Combine"],
  "sanitizers": ["SqlParameter", "Parameters.Add", "HttpUtility.HtmlEncode", "AntiXss"],
  "auth_markers": ["[Authorize]", "User.IsInRole", "RequireAuthorization", "[Authorize("]
}
```