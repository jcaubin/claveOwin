using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace eu.stork.peps.auth.Service
{
    public class SamlPersonalData
    {
        public string eIdentifier { get; set; }
        public string GivenName { get; set; }
        public string Surname { get; set; }
        public string InheritedFamilyName { get; set; }
        public string Email { get; set; }
    }
}
