// Intentionally vulnerable ASP.NET minimal API for OSWE auditor validation. DO NOT DEPLOY.
using System.Diagnostics;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// VULN (step 1 - forgeable auth cookie): authorization trusts a raw, unsigned client cookie.
static bool IsAdmin(HttpRequest request) => request.Cookies["admin"] == "1";

app.MapGet("/admin/ping", (HttpRequest request) =>
{
    if (!IsAdmin(request))
        return Results.StatusCode(403);

    var host = request.Query["host"].ToString();
    // VULN (step 2 - command injection -> RCE): host is concatenated into a shell command string
    // and run via /bin/sh, e.g. host = "127.0.0.1; id"
    var psi = new ProcessStartInfo
    {
        FileName = "/bin/sh",
        Arguments = "-c \"ping -c 1 " + host + "\"",
        RedirectStandardOutput = true,
        UseShellExecute = false
    };
    using var proc = Process.Start(psi)!;
    var output = proc.StandardOutput.ReadToEnd();
    proc.WaitForExit();
    return Results.Text(output);
});

app.Run();
