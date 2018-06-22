using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using eu.stork.peps.auth.Service;
using Kentor.AuthServices.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace ClaveAuthOwin
{
    // Created by the factory in the DummyAuthenticationMiddleware class.
    internal class ClaveAuthenticationHandler : AuthenticationHandler<ClaveAuthenticationOptions>
    {
        /// <summary>
        /// Origina la petición de autenticacion a cl@ve
        /// </summary>
        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                // Only react to 401 if there is an authentication challenge for the authentication
                // type of this handler.
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
                if (challenge != null)
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

        /// <summary>
        /// Recibe la respuesta de autenticacion proveniente de cl@ve
        /// </summary>
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
            string rp = Request.Query["reqPath"];
            AuthenticationProperties authProp = Options.StateDataFormat.Unprotect(rp);

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