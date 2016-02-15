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

                    SamlService claveSrv = new SamlService();
                    var commandResult = claveSrv.GetSamlCommandResult(stateString);
                    commandResult.Apply(Context);
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
                    if (ticket.Identity != null)
                    {
                        Context.Authentication.SignIn(ticket.Properties, ticket.Identity);
                    }
                    Response.Redirect(ticket.Properties.RedirectUri);

                    // Prevent further processing by the owin pipeline.
                    return true;
                }
            }
            // Let the rest of the pipeline run.
            return false;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            var rp = Request.Query["reqPath"];
            var state = Options.StateDataFormat.Unprotect(rp);
            var authProp = new AuthenticationProperties();
            authProp.RedirectUri = state.RedirectUri;

            SamlService claveSvc = new SamlService();
            var commandResult = claveSvc.GetSamlResponseCommandResult(await Context.ToHttpRequestData());
            if (commandResult.Principal != null)
            {
                var identity = commandResult.Principal.Identities
                    .Select(i => new ClaimsIdentity(i, null, Options.SignInAsAuthenticationType, i.NameClaimType, i.RoleClaimType)).FirstOrDefault();
                return new AuthenticationTicket(identity, authProp);
            }
            else
            {
                return new AuthenticationTicket(null, authProp);
            }
        }
    }
}
