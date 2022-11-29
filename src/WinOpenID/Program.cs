using Microsoft.AspNetCore.Authentication.Negotiate;
using WinOpenID;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();

builder.Services.AddCors();

builder.Services.AddWinOpenId(builder.Configuration);

var app = builder.Build();

app.UseWinOpenID();

app.MapGet("/", () => Results.Redirect(".well-known/openid-configuration/"));

app.Run();
