/*
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 * 
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

//
// author: AMA – Agência para a Modernização Administrativa IP, PORTUGAL (www.ama.pt)
//
namespace eu.stork.peps.auth.engine
{
    public class SAMLLogoutRequest
    {
        public string Id
        {
            get;
            set;
        }

        public string Country
        {
            get;
            set;
        }

        public string Alias
        {
            get;
            set;
        }

        public string Destination
        {
            get;
            set;
        }

        public string Issuer
        {
            get;
            set;
        }
        
        public string NameID
        {
            get;
            set;
        }

        public string QAALevel
        {
            get;
            set;
        }

        public string SpProvidedId
        {
            get;
            set;
        }

        public override string ToString()
        {
            String str = "SAMLLogoutRequest(";
            if (!string.IsNullOrEmpty(Issuer)) str += "Issuer: " + Issuer;
            if (!string.IsNullOrEmpty(Destination)) str += ", Destination: " + Destination;
            if (!string.IsNullOrEmpty(Id)) str += ", Id: " + Id;
            if (!string.IsNullOrEmpty(Alias)) str += ", Alias: " + Alias;
            str += ")";
            return str;
        }
    }
}
