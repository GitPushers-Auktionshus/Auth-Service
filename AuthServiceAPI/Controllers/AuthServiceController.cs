using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using MongoDB.Driver;
using MongoDB.Bson;
using AuthServiceAPI.Model;
using DnsClient;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using AuthServiceAPI.Service;

namespace AuthServiceAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthServiceController : ControllerBase
{
    private readonly ILogger<AuthServiceController> _logger;

    private readonly IConfiguration _config;

    private readonly IAuthenticationRepository _service;

    public AuthServiceController(ILogger<AuthServiceController> logger, IConfiguration config, IAuthenticationRepository service)
    {
        _logger = logger;
        _config = config;
        _service = service;
    }

    // Login POST - Authorizes a user and returns a JWT-token
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserDTO userDTO)
    {
        _logger.LogInformation("Login Endpoint reached");

        // Checks if user is authorized or not.If it is, it will generate a string JWT token and return it
        string authorizedStatus = await _service.LoginUser(userDTO);
        if (authorizedStatus == "Unauthorized")
        {
            return Unauthorized();
        }
        else if (authorizedStatus == "Authorized")
        {
            var token = _service.GenerateJwtTokenToUser(userDTO.Username);

            return Ok(new { token });
        }
        else
        {
            return Unauthorized();
        }
    }
}
