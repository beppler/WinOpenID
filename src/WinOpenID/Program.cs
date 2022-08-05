using Microsoft.AspNetCore.Authentication.Negotiate;
using WinOpenID;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();

var serverOptions = builder.Configuration.GetSection(WinOpenIDOptions.Server).Get<WinOpenIDOptions>();

builder.Services.AddWinOpenId(serverOptions);

var app = builder.Build();

// Configure CORS
app.UseCors(builder => builder.WithOrigins(serverOptions.AllowedOrigins).AllowAnyMethod().AllowAnyHeader());

app.UseRouting();

app.UseAuthentication();

app.MapGet("/", () => Results.Extensions.Html(@"<!doctype html>
<html>
    <head><title>WinOpenID</title></head>
    <body>
        <p>Windows Authorization Server <a href='.well-known/openid-configuration\'>(Configuration)</a></p>
    </body>
</html>"));

app.Run();
