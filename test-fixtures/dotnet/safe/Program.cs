// Hardened ASP.NET minimal API (negative fixture). DO NOT DEPLOY.
using System.Diagnostics;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Safe: the secret comes from the ENVIRONMENT only — there is NO hardcoded/default secret in the source
// (a white-box reader cannot recover it). If unset, deny. A raw client cookie is never trusted.
var adminToken = Environment.GetEnvironmentVariable("ADMIN_TOKEN");
bool IsAdmin(HttpRequest request) =>
    !string.IsNullOrEmpty(adminToken) && request.Headers["X-Auth-Token"] == adminToken;

app.MapGet("/admin/ping", (HttpRequest request) =>
{
    if (!IsAdmin(request))
        return Results.StatusCode(403);

    var host = request.Query["host"].ToString();
    // Safe: strict allow-list, then execute with an argument LIST and no shell.
    if (!Regex.IsMatch(host, "^[a-z0-9.-]+$", RegexOptions.IgnoreCase))
        return Results.BadRequest();

    var psi = new ProcessStartInfo
    {
        FileName = "ping",
        RedirectStandardOutput = true,
        UseShellExecute = false
    };
    psi.ArgumentList.Add("-c");
    psi.ArgumentList.Add("1");
    psi.ArgumentList.Add(host);
    using var proc = Process.Start(psi)!;
    var output = proc.StandardOutput.ReadToEnd();
    proc.WaitForExit();
    return Results.Text(output);
});

app.Run();
