﻿using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthServiceAPI.Controllers;
using AuthServiceAPI.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;

namespace AuthServiceAPI.Service
{
    public class MongoDBService : IAuthenticationRepository
    {
        // Initializes logger
        private readonly ILogger<MongoDBService> _logger;

        // Initializes enviroment variables
        private readonly string _usersDatabase;
        private readonly string _userCollection;
        private readonly string? _secret;
        private readonly string? _issuer;
        private readonly string? _salt;
        private readonly string _connectionURI;

        // Initializes MongoDB database collection
        private readonly IMongoCollection<User> _users;
        private readonly IConfiguration _config;

        public MongoDBService(ILogger<MongoDBService> logger, IConfiguration config, EnvVariables vaultSecrets)
        {
            _logger = logger;
            _config = config;

            try
            {
                // Retrieves enviroment variables from dockercompose file
                _usersDatabase = config["UsersDatabase"] ?? "UsersDatabase missing";
                _userCollection = config["UserCollection"] ?? "UserCollection missing";

                // Retrieves enviroment variables from program.cs, from injected EnviromentVariables class 
                _secret = vaultSecrets.dictionary["Secret"];
                _issuer = vaultSecrets.dictionary["Issuer"];
                _salt = vaultSecrets.dictionary["Salt"];
                _connectionURI = vaultSecrets.dictionary["ConnectionURI"];

                _logger.LogInformation($"AuthService variables loaded in Auth-controller: Secret: {_secret}, Issuer: {_issuer}, Salt: {_salt}, ConnectionURI: {_connectionURI}, DatabaseName: {_usersDatabase}, CollectionName: {_userCollection}");

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
                var userDatabase = mongoClient.GetDatabase(_usersDatabase);
                _logger.LogInformation($"[*] DATABASE: {_usersDatabase}");


                // Sets MongoDB Collection
                _users = userDatabase.GetCollection<User>(_userCollection);
                _logger.LogInformation($"[*] COLLECTION: {_userCollection}");

            }
            catch (Exception ex)
            {
                _logger.LogError($"Error trying to connect to database: {ex.Message}");

                throw;
            }

        }

        public async Task<string> LoginUser(UserDTO userDTO)
        {
            try
            {
                _logger.LogInformation($"Authenticating user: {userDTO.Username}");

                // Looks up our user in the DB
                User user = await _users.Find(u => u.Username == userDTO.Username).FirstOrDefaultAsync<User>();

                // Checks if user exists. If it doesn't or/and the password provided is false it returns unauthorized.
                // Otherwise it returns authorized
                if (user == null)
                {
                    _logger.LogError("User not found");

                    return "Unauthorized";
                }
                else if (user.Username != userDTO.Username)
                {
                    _logger.LogError("User not found");

                    return "Unauthorized";
                }
                else
                {
                    // Hashes the provided password with the same salt used for creating the user
                    string hashedPassword = HashPassword(userDTO.Password, _salt);

                    // If the hashed password is the same as the one in the database, the user i authorized
                    if (hashedPassword == user.Password)
                    {
                        _logger.LogInformation("User authorized");

                        return "Authorized";
                    }
                    // If it doesn't match, the user is not authorized
                    else
                    {
                        _logger.LogError("Wrong password");

                        return "Unauthorized";
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error running login: {ex.Message}");

                throw;
            }
        }

        // Generates a new JWT token including the user's username 
        public string GenerateJwtTokenToUser(string username)
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
                expires: DateTime.Now.AddMinutes(1440),
                signingCredentials: credentials);

            _logger.LogInformation($"Generated token for user {username}");

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Method for password hashing.
        // Using BCrypt-package to salt and hash a password string.
        public static string HashPassword(string password, string salt)
        {
            string hashSalt = salt;
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password, salt);

            return hashedPassword;
        }

    }
}

