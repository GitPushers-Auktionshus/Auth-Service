using AuthServiceAPI.Controllers;
using AuthServiceAPI.Model;
using AuthServiceAPI.Service;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;

namespace AuthServiceAPI.Test;

public class AuthServiceTest
{
    private ILogger<AuthServiceController> _logger = null!;
    private IConfiguration _configuration = null!;

    [SetUp]
    public void Setup()
    {
        _logger = new Mock<ILogger<AuthServiceController>>().Object;

        var myConfiguration = new Dictionary<string, string?>
        {
            {"UsersServiceBrokerHost", "http://testhost.local"}
        };

        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(myConfiguration)
            .Build();
    }

    // Tests that the method returns an OkObjectResult, when the user is auhtorized
    [Test]
    public async Task TestUserLoginEndpoint_Authorized()
    {
        UserDTO userDTO = new UserDTO
        {
            Username = "Jacob",
            Password = "1234"
        };

        var stubRepo = new Mock<IAuthenticationRepository>();


        stubRepo.Setup(svc => svc.LoginUser(userDTO))
            .ReturnsAsync("Authorized");

        stubRepo.Setup(svc => svc.GenerateJwtTokenToUser(userDTO.Username))
            .Returns("generatedJWTtoken");

        var controller = new AuthServiceController(_logger, _configuration, stubRepo.Object);

        // Act        
        var result = await controller.Login(userDTO);

        // Assert
        Assert.That(result, Is.TypeOf<OkObjectResult>());
        
    }

    // Tests that the method returns an UnauthorizedResult when the user isnt authorized
    [Test]
    public async Task TestUserLoginEndpoint_Unauthorized()
    {
        UserDTO userDTO = new UserDTO
        {
            Username = "Jacob",
            Password = "1234"
        };

        var stubRepo = new Mock<IAuthenticationRepository>();


        stubRepo.Setup(svc => svc.LoginUser(userDTO))
            .ReturnsAsync("Unauthorized");

        stubRepo.Setup(svc => svc.GenerateJwtTokenToUser(userDTO.Username))
            .Returns("generatedJWTtoken");

        var controller = new AuthServiceController(_logger, _configuration, stubRepo.Object);

        // Act        
        var result = await controller.Login(userDTO);

        // Assert
        Assert.That(result, Is.TypeOf<UnauthorizedResult>());

    }

    // Tests that the method returns a bad request, if an exception occurs anywhere in the LoginUser method
    [Test]
    public async Task TestUserLoginEndpoint_Error()
    {
        UserDTO userDTO = new UserDTO
        {
            Username = "Jacob",
            Password = "1234"
        };

        var stubRepo = new Mock<IAuthenticationRepository>();


        stubRepo.Setup(svc => svc.LoginUser(userDTO))
            .ThrowsAsync(new Exception());

        stubRepo.Setup(svc => svc.GenerateJwtTokenToUser(userDTO.Username))
            .Returns("generatedJWTtoken");

        var controller = new AuthServiceController(_logger, _configuration, stubRepo.Object);

        // Act        
        var result = await controller.Login(userDTO);

        // Assert
        Assert.That(result, Is.TypeOf<BadRequestResult>());

    }
}