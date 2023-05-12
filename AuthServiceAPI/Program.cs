using System.Security.AccessControl;
using System.Security.Claims;
using System.Text;
using AuthServiceAPI.Model;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using NLog;
using NLog.Web;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("init main");

try
{
    var builder = WebApplication.CreateBuilder(args);


    string hostnameVault = Environment.GetEnvironmentVariable("HostnameVault") ?? "none";

    var EndPoint = $"http://{hostnameVault}:8200/";
    var httpClientHandler = new HttpClientHandler();
    httpClientHandler.ServerCertificateCustomValidationCallback =
    (message, cert, chain, sslPolicyErrors) => { return true; };

    // Initialize one of the several auth methods.
    IAuthMethodInfo authMethod =
    new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
    // Initialize settings. You can also set proxies, custom delegates etc. here.
    var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
    {
        Namespace = "",
        MyHttpClientProviderFunc = handler => new HttpClient(httpClientHandler)
        {
            BaseAddress = new Uri(EndPoint)
        }
    };

    IVaultClient vaultClient = new VaultClient(vaultClientSettings);

    // Use client to read a key-value secret.
    Secret<SecretData> enviromentVariables = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "enviromentVariables", mountPoint: "secret");
    Secret<SecretData> connectionString = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "connectionStrings", mountPoint: "secret");

    string? secret = enviromentVariables.Data.Data["Secret"].ToString();
    string? issuer = enviromentVariables.Data.Data["Issuer"].ToString();
    string? connectionURI = connectionString.Data.Data["ConnectionURI"].ToString();

    EnviromentVariables test = new EnviromentVariables
    {
        dictionary = new Dictionary<string, string>
        {
            { "Secret", secret },
            { "Issuer", issuer },
            { "ConnectionURI", connectionURI }
        }
    };

    builder.Services.AddSingleton<EnviromentVariables>(test);


    logger.Info($"Variables loaded in program.cs: Secret: {secret}, Issuer: {issuer}, ConnectionURI : {connectionURI}");

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
    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

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
    NLog.LogManager.Shutdown();
}
