namespace Demo.Controllers;

using Demo.Services;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/di")]
public class DiController : ControllerBase
{
    private readonly IRunner _runner;

    public DiController(IRunner runner)
    {
        _runner = runner;
    }

    [HttpPost("run")]
    public IActionResult Run([FromBody] string cmd)
    {
        _runner.Run(cmd);
        return Ok();
    }
}
