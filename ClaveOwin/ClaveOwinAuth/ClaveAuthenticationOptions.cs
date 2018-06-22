using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace ClaveAuthOwin
{
    public class ClaveAuthenticationOptions : AuthenticationOptions
    {
        public ClaveAuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
            Description.Caption = Constants.DefaultAuthenticationType;
            AuthenticationMode = AuthenticationMode.Passive;
        }

        public PathString CallbackPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
    }
}