using Microsoft.Extensions.Options;

namespace WinOpenID;

public static class WinOpenIDMiddlewareExtensions
{
    public static IApplicationBuilder UseWinOpenID(this IApplicationBuilder app)
    {
        var serverOptions = app.ApplicationServices.GetRequiredService<IOptions<WinOpenIDOptions>>().Value;

        app.UseCors(builder => builder.AllowAnyHeader().WithMethods("GET", "POST").WithOrigins(serverOptions.AllowedOrigins));

        app.UseAuthentication();

        return app;
    }
}
