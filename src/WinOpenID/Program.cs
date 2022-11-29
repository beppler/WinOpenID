using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.Extensions.Options;
using WinOpenID;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();

builder.Services.AddCors();

builder.Services.AddWinOpenId(builder.Configuration);

var app = builder.Build();

var serverOptions = app.Services.GetRequiredService<IOptions<WinOpenIDOptions>>().Value;

app.UseCors(builder => builder.AllowAnyHeader().WithMethods("GET", "POST").WithOrigins(serverOptions.AllowedOrigins));

app.UseAuthentication();

app.MapGet("/", () => Results.Redirect(".well-known/openid-configuration/"));

app.Run();
