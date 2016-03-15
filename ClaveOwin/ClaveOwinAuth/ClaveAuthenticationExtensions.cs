using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
