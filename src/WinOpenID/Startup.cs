using System;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace WinOpenID
{
    // Source: https://github.com/auroris/OpenIddict-WindowsAuth
    public class Startup
    {
        public IConfiguration Configuration { get; }
        public ServerOptions ServerOptions { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            ServerOptions = Configuration.GetSection(ServerOptions.Server).Get<ServerOptions>();
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {

            // Add cross-origin resource sharing for Javascript clients
            services.AddCors();

            services.AddAuthentication();

            // Attach OpenIddict with a ton of options
            services.AddOpenIddict().AddServer(options =>
            {
                // This OpenIddict server is stateless; however, make sure IIS doesn't dispose of the application too often (ie, via app pool recycles or shut downs due to inactivity)
                options.AddEphemeralSigningKey().AddEphemeralEncryptionKey();
                if (!ServerOptions.EncryptAccessToken)
                    options.DisableAccessTokenEncryption();
                options.AllowAuthorizationCodeFlow();
                options.AllowImplicitFlow();
                options.SetAuthorizationEndpointUris("/connect/authorize")
                       .SetTokenEndpointUris("/connect/token");
                options.EnableDegradedMode(); // We'll handle protocol stuff ourselves; don't want user stores or such
                options.UseAspNetCore()
                    .DisableTransportSecurityRequirement(); // Disable the need for HTTPS in dev
                options.RegisterScopes(Scopes.OpenId, Scopes.Email, Scopes.Profile, Scopes.Roles); // Tell OpenIddict that we support these scopes
                options.RegisterClaims(
                    Claims.Name, Claims.PreferredUsername, Claims.Email, Claims.GivenName, Claims.FamilyName,
                    Claims.EmailVerified, Claims.PhoneNumber, Claims.PhoneNumberVerified,
                    Claims.Role, "employee_id"
                );


                // Event handler for validating token requests
                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        // I accept all context.ClientId's, so just carry on.
                        return default;
                    }));

                // Event handler for validating authorization requests
                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        // Verification: I accept all context.ClientId's, but do check to see if the context.RedirectUri is proper
                        foreach (string host in ServerOptions.AllowedHosts)
                        {
                            if (context.RedirectUri.StartsWith(host, StringComparison.InvariantCultureIgnoreCase))
                            {
                                return default;
                            }
                        }

                        // Fall-through: URL was not proper.
                        context.Reject(error: Errors.InvalidClient, description: "The specified 'redirect_uri' is not valid for this client application.");
                        return default;
                    }));

                // Event handler for authorization requests
                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(async context =>
                    {
                        // Get the HTTP request
                        HttpRequest request = context.Transaction.GetHttpRequest() ?? throw new InvalidOperationException("The ASP.NET Core request cannot be retrieved.");

                        // Try to get the authentication of the current session via Windows Authentication
                        AuthenticateResult result = await request.HttpContext.AuthenticateAsync("Windows");

                        if (!(result?.Principal is WindowsPrincipal wp))
                        {
                            // Run Windows authentication
                            await request.HttpContext.ChallengeAsync("Windows");
                            context.HandleRequest();
                            return;
                        }

                        // If we're authenticated using Windows authentication, build an Identity with Claims;
                        ClaimsIdentity identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);

                        // Set the directory service to the active directory domain or machine 
                        using PrincipalContext directoryService = ServerOptions.UseDomain
                            ? new PrincipalContext(ContextType.Domain, ServerOptions.Domain)
                            : new PrincipalContext(ContextType.Machine);

                        // Get information about the user
                        UserPrincipal user = UserPrincipal.FindByIdentity(directoryService, result.Principal.FindFirstValue(ClaimTypes.Name));

                        if (user == null)
                        {
                            context.Reject(error: Errors.InvalidGrant, description: "User is not found.");
                            return;
                        }

                        // Attach basic id if requested
                        if (context.Request.HasScope(Scopes.OpenId))
                        {
                            // Add the name identifier claim; this is the user's unique identifier
                            string subject = ServerOptions.UseDomain
                                ? user.Guid.ToString()
                                : user.Sid.Value;
                            identity.AddClaim(Claims.Subject, subject, Destinations.AccessToken);
                        }

                        // Attach email address if requested
                        if (context.Request.HasScope(Scopes.Email))
                        {
                            // Add the user's email address
                            if (user.EmailAddress != null)
                            {
                                identity.AddClaim(Claims.Email, user.EmailAddress, Destinations.IdentityToken);
                                identity.AddClaim(new Claim(Claims.EmailVerified, "true", ClaimValueTypes.Boolean).SetDestinations(Destinations.IdentityToken));
                            }
                        }

                        // Attach profile stuff if requested
                        if (context.Request.HasScope(Scopes.Profile))
                        {
                            // Add the account's friendly name
                            identity.AddClaim(Claims.Name, user.DisplayName, Destinations.IdentityToken);

                            // Add the user name
                            identity.AddClaim(Claims.Username, user.Name, Destinations.AccessToken, Destinations.IdentityToken);

                            // Add the user's windows username
                            string ntUsername = user.Sid.Translate(typeof(NTAccount)).Value;
                            identity.AddClaim(Claims.PreferredUsername, ntUsername, Destinations.AccessToken, Destinations.IdentityToken);

                            // Add the employee id number
                            if (user.EmployeeId != null) { identity.AddClaim("employee_id", user.EmployeeId, Destinations.AccessToken, Destinations.IdentityToken); }

                            // Add the user's name
                            if (user.GivenName != null) { identity.AddClaim(Claims.GivenName, user.GivenName, Destinations.IdentityToken); }
                            if (user.Surname != null) { identity.AddClaim(Claims.FamilyName, user.Surname, Destinations.IdentityToken); }
                        }

                        // Attach phone number if requested
                        if (context.Request.HasScope(Scopes.Phone))
                        {
                            // Telephone 
                            if (user.VoiceTelephoneNumber != null)
                            {
                                identity.AddClaim(Claims.PhoneNumber, user.VoiceTelephoneNumber, Destinations.IdentityToken);
                                identity.AddClaim(new Claim(Claims.PhoneNumberVerified, "true", ClaimValueTypes.Boolean).SetDestinations(Destinations.IdentityToken));
                            }
                        }

                        // Attach roles if requested
                        if (context.Request.HasScope(Scopes.Roles))
                        {
                            // Get and assign the group claims
                            foreach (Principal group in user.GetGroups())
                            {
                                if (group.Name != null)
                                {
                                    identity.AddClaim(Claims.Role, group.Name, Destinations.IdentityToken);
                                }
                            }
                        }

                        // Attach the principal to the authorization context, so that an OpenID Connect response
                        // with an authorization code can be generated by the OpenIddict server services.
                        context.Principal = new ClaimsPrincipal(identity);
                    }));
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // Configure CORS
            app.UseCors(builder =>
            {
                builder.WithOrigins(ServerOptions.AllowedOrigins);
                builder.AllowAnyMethod();
                builder.AllowAnyHeader();
            });

            app.UseRouting();
            app.UseAuthentication();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet("/", async context =>
                {
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync("Windows Authorization Server <a href=\".well-known/openid-configuration\">(Configuration)</a>");
                });
            });
        }
    }
}
