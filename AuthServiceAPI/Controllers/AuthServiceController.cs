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

namespace AuthServiceAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthServiceController : ControllerBase
{
    private readonly ILogger<AuthServiceController> _logger;

    private readonly string _secret;
    private readonly string _issuer;
    private readonly string _connectionURI;
    private readonly string _databaseName;
    private readonly string _collectionName;


    private readonly IMongoCollection<User> _users;
    private readonly IConfiguration _config;

    public AuthServiceController(ILogger<AuthServiceController> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;

        _secret = config["Secret"] ?? "Secret missing";
        _issuer = config["Issuer"] ?? "Issue'er missing";
        _connectionURI = config["ConnectionURI"] ?? "ConnectionURI missing";
        _databaseName = config["DatabaseName"] ?? "DatabaseName missing";
        _collectionName = config["CollectionName"] ?? "CollectionName missing";



        _logger.LogInformation($"AuthService variables: Secret: {_secret}, Issuer: {_issuer}, ConnectionURI: {_connectionURI}, DatabaseName: {_databaseName}, CollectionName: {_collectionName}");


        try
        {
            // Client
            var mongoClient = new MongoClient(_connectionURI);
            _logger.LogInformation($"[*] CONNECTION_URI: {_connectionURI}");

            // Database
            var database = mongoClient.GetDatabase(_databaseName);
            _logger.LogInformation($"[*] DATABASE: {_databaseName}");

            // Collection
            _users = database.GetCollection<User>(_collectionName);
            _logger.LogInformation($"[*] COLLECTION: {_collectionName}");

        }
        catch (Exception ex)
        {
            _logger.LogError($"Fejl ved oprettelse af forbindelse: {ex.Message}");
            throw;
        }
    }

    // Login POST - Godkender legitimationsoplysninger og udsteder JWT-token
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserDTO userDTO)
    {
        try
        {
            _logger.LogInformation($"Authenticating user: {userDTO.Username}");

            //Looks up our user in the DB
            User user = await _users.Find(u => u.Username == userDTO.Username).FirstOrDefaultAsync<User>();

            if (user == null)
            {
                _logger.LogError("User not found");

                return Unauthorized();
            }
            else if (user.Username != userDTO.Username)
            {
                _logger.LogError("User not found");

                return Unauthorized();
            }
            else if (user.Password != userDTO.Password)
            {
                _logger.LogError("Wrong password");

                return Unauthorized();
            }
            else
            {
                var token = GenerateJwtToken(user.Username);

                return Ok(new { token });
            }

        }
        catch (Exception ex)
        {
            _logger.LogError($"Error running login: {ex.Message}");

            throw;
        }
    }

    // Generates a JWT-token using a users username
    private string GenerateJwtToken(string username)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));

        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
           new Claim(ClaimTypes.NameIdentifier, username),
        };

        var token = new JwtSecurityToken(
            _issuer,
            "http://localhost",
            claims,
            expires: DateTime.Now.AddMinutes(60),
            signingCredentials: credentials);

        _logger.LogInformation($"Generated token for user {username}");

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
