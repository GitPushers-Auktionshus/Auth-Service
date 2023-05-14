using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace AuthServiceAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthTestController : ControllerBase
{
    private readonly ILogger<AuthTestController> _logger;

    public AuthTestController(ILogger<AuthTestController> logger)
    {
        _logger = logger;
    }

    // Tests if verification works and authorizes. Returns unauthorized if not
    [Authorize]
    [HttpGet("all")]
    public async Task<IActionResult> Get()
    {
        return Ok("You're authorized");
    }
}
