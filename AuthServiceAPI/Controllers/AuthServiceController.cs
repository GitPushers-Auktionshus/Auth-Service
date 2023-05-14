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

 

namespace AuthServiceAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthServiceController : ControllerBase
{
    private readonly ILogger<AuthServiceController> _logger;

    // Initializes enviroment variables
    private readonly string _hostnameVault;
    private readonly string _databaseName;
    private readonly string _collectionName;
    private readonly string? _secret;
    private readonly string? _issuer;
    private readonly string _connectionURI;

    // Initializes MongoDB database collection
    private readonly IMongoCollection<User> _users;
    private readonly IConfiguration _config;

    public AuthServiceController(ILogger<AuthServiceController> logger, IConfiguration config, EnviromentVariables vaultSecrets)
    {
        _logger = logger;
        _config = config;

        try
        {
            // Retrieves enviroment variables from dockercompose file
            _hostnameVault = config["HostnameVault"] ?? "HostnameVault missing";
            _databaseName = config["DatabaseName"] ?? "DatabaseName missing";
            _collectionName = config["CollectionName"] ?? "CollectionName missing";

            // Retrieves enviroment variables from program.cs, from injected EnviromentVariables class 
            _secret = vaultSecrets.dictionary["Secret"];
            _issuer = vaultSecrets.dictionary["Issuer"];
            _connectionURI = vaultSecrets.dictionary["ConnectionURI"];

            _logger.LogInformation($"AuthService variables loaded in Auth-controller: Secret: {_secret}, Issuer: {_issuer}, ConnectionURI: {_connectionURI}, DatabaseName: {_databaseName}, CollectionName: {_collectionName}");
        }
        catch (Exception ex)
        {
            _logger.LogError("Error retrieving enviroment variables");

            throw;
        }

        try
        {
            // Sets MongoDB client
            var mongoClient = new MongoClient(_connectionURI);
            _logger.LogInformation($"[*] CONNECTION_URI: {_connectionURI}");

            // Sets MongoDB Database
            var database = mongoClient.GetDatabase(_databaseName);
            _logger.LogInformation($"[*] DATABASE: {_databaseName}");

            // Sets MongoDB Collection
            _users = database.GetCollection<User>(_collectionName);
            _logger.LogInformation($"[*] COLLECTION: {_collectionName}");

        }
        catch (Exception ex)
        {
            _logger.LogError($"Fejl ved oprettelse af forbindelse: {ex.Message}");
            throw;
        }
    }

    // Login POST - Authorizes a user and returns a JWT-token
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserDTO userDTO)
    {
        try
        {
            _logger.LogInformation($"Authenticating user: {userDTO.Username}");

            //Looks up our user in the DB
            User user = await _users.Find(u => u.Username == userDTO.Username).FirstOrDefaultAsync<User>();

            // Checks if user exists. If it doesn't or/and the password provided is false it returns unauthorized.
            // Otherwise it returns a generated JWT-token
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
                // Calls the method that generates the token including the users username

                _logger.LogInformation("User authorized");

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
