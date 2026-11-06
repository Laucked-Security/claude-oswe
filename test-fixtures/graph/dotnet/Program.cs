using Demo.Services;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/health", () => "ok");
app.MapPost("/exec", (string cmd, Runner r) => r.Run(cmd)).RequireAuthorization();

app.Run();
