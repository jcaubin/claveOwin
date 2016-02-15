using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using eu.stork.peps.auth.Service;
using Kentor.AuthServices.Owin;

namespace DummyOwinAuth
{
    // Created by the factory in the DummyAuthenticationMiddleware class.
    class ClaveAuthenticationHandler : AuthenticationHandler<ClaveAuthenticationOptions>
    {
        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
                if (challenge != null)
                // Only react to 401 if there is an authentication challenge for the authentication 
                // type of this handler.
                {
                    var state = challenge.Properties;

                    if (string.IsNullOrEmpty(state.RedirectUri))
                    {
                        state.RedirectUri = Request.Uri.ToString();
                    }

                    var stateString = Options.StateDataFormat.Protect(state);

                    //string reqPath = "test";
                    //Response.Redirect(WebUtilities.AddQueryString(Options.CallbackPath.Value, "state", stateString));
                    SamlService svc = new SamlService();
                    var r2 = svc.GetSamlCommandResult(stateString);
                    r2.Apply(Context);
                }
            }
            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            // This is always invoked on each request. For passive middleware, only do anything if this is
            // for our callback path when the user is redirected back from the authentication provider.
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                var ticket = await AuthenticateAsync();
                if (ticket != null)
                {
                    var rp = Request.Query["reqPath"];
                    var state = Options.StateDataFormat.Unprotect(rp);

                    Context.Authentication.SignIn(ticket.Properties, ticket.Identity);
                    Response.Redirect(state.RedirectUri);
                    
                    // Prevent further processing by the owin pipeline.
                    return true;
                }
            }
            // Let the rest of the pipeline run.
            return false;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            SamlService claveSvc = new SamlService();
            var commandResult = claveSvc.GetSamlResponseCommandResult(await Context.ToHttpRequestData());
            var ident2 = commandResult.Principal.Identities
                .Select(i => new ClaimsIdentity(i, null, Options.SignInAsAuthenticationType, i.NameClaimType, i.RoleClaimType)).FirstOrDefault();

            return new AuthenticationTicket(ident2, new AuthenticationProperties());
        }
    }
}
