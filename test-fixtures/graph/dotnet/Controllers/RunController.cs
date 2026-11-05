namespace Demo.Controllers;

using Demo.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

[ApiController]
[Route("api/[controller]")]
public class RunController : ControllerBase
{
    private readonly Runner _runner;

    public RunController(Runner runner)
    {
        _runner = runner;
    }

    [HttpPost("run")]
    [Authorize]
    public IActionResult Run([FromBody] string cmd)
    {
        _runner.Run(cmd);
        return Ok();
    }

    [HttpGet("ping")]
    [AllowAnonymous]
    public string Ping() => "pong";

    [HttpGet("find")]
    public string Find([FromQuery] string q) => q;
}
