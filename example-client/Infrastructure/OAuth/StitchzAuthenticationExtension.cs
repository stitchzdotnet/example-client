using Owin;
using System;

namespace example_client.Infrastructure.OAuth
{
    public static class StitchzAuthenticationExtension
    {
        public static IAppBuilder UseStitchzAuthentication(this IAppBuilder app,
            StitchzAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(StitchzAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseStitchzAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseStitchzAuthentication(new StitchzAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}