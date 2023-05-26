using System.Security.AccessControl;
using System.Security.Claims;
using System.Text;
using AuthServiceAPI.Model;
using AuthServiceAPI.Service;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using NLog;
using NLog.Web;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;

// Sets up NLog as default loggingtool 
var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

logger.Debug("init main");

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Retrieves Vault hostname from dockercompose file
    string hostnameVault = Environment.GetEnvironmentVariable("HostnameVault") ?? "none";

    // Sets up the Vault using the endpoint of the Vault
    var EndPoint = $"http://{hostnameVault}:8200/";
    var httpClientHandler = new HttpClientHandler();
    httpClientHandler.ServerCertificateCustomValidationCallback =
    (message, cert, chain, sslPolicyErrors) => { return true; };

    // Initialize one of the several auth methods.
    IAuthMethodInfo authMethod =
    new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");

    // Initialize vault settings.
    var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
    {
        Namespace = "",
        MyHttpClientProviderFunc = handler => new HttpClient(httpClientHandler)
        {
            BaseAddress = new Uri(EndPoint)
        }
    };

    // Initialize vault client
    IVaultClient vaultClient = new VaultClient(vaultClientSettings);

    // Uses vault client to read key-value secrets.

    Secret<SecretData> environmentVariables = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "environmentVariables", mountPoint: "secret");
    Secret<SecretData> connectionString = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "connectionStrings", mountPoint: "secret");

    // Initialized string variables to store enviroment secrets
    string? secret = environmentVariables.Data.Data["Secret"].ToString();
    string? issuer = environmentVariables.Data.Data["Issuer"].ToString();
    string? salt = environmentVariables.Data.Data["Salt"].ToString();
    string? connectionURI = connectionString.Data.Data["ConnectionURI"].ToString();

    // Creates and EnviromentVariable object with a dictionary to contain the secrets
    EnvVariables vaultSecrets = new EnvVariables
    {
        dictionary = new Dictionary<string, string>
        {
            { "Secret", secret },
            { "Issuer", issuer },
            { "ConnectionURI", connectionURI },
            { "Salt", salt }
        }
    };

    // Adds the EnviromentVariable object to the project as a singleton.
    // It can now be accessed wihtin the entire projekt
    builder.Services.AddSingleton<EnvVariables>(vaultSecrets);
    builder.Services.AddSingleton<IAuthenticationRepository, MongoDBService>();


    logger.Info($"Variables loaded in program.cs: Secret: {secret}, Issuer: {issuer}, ConnectionURI : {connectionURI}, Salt : {salt}");

    // Adds functionality allowing our project to verify JWT-tokens
    builder.Services
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = issuer,
                IssuerSigningKey =
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))
            };
        }
        );


    // Add services to the container.
    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("Admin", policy => policy.RequireClaim(ClaimTypes.Role, "admin"));
    });


    // Adds NLog to our project
    builder.Logging.ClearProviders();
    builder.Host.UseNLog();

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();

    app.UseAuthentication();

    app.UseAuthorization();

    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    logger.Error(ex, "Stopped program because of exception");
    throw;
}
finally
{
    // Shuts down NLog
    NLog.LogManager.Shutdown();
}
