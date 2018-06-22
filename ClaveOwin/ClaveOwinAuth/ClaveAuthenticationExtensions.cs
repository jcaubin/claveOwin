using Owin;

namespace ClaveAuthOwin
{
    public static class ClaveAuthenticationExtensions
    {
        public static IAppBuilder UseClaveAuthentication(this IAppBuilder app, ClaveAuthenticationOptions options)
        {
            return app.Use(typeof(ClaveAuthenticationMiddleware), app, options);
        }
    }
}