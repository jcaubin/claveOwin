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
    public class SAMLRequest
    {
        private List<AttributeElement> attributes = new List<AttributeElement>();

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

        public string AssertionConsumerServiceURL
        {
            get;
            set;
        }

        public string ProviderName
        {
            get;
            set;
        }

        public string Issuer
        {
            get;
            set;
        }

        public string IssuerFormat
        {
            get;
            set;
        }


        public string QAALevel
        {
            get;
            set;
        }

        internal List<AttributeElement> Attributes
        {
            get { return attributes; }
        }

        public void AddAttribute(string attrName, bool isRequired)
        {
            attributes.Add(new AttributeElement(attrName, isRequired));
        }

        public void AddAttribute(string attrName, string value, int attrStatus)
        {
            attributes.Add(new AttributeElement(attrName, value, attrStatus));
        }

        public override string ToString()
        {
            String str = "SAMLRequest(";
            if (!string.IsNullOrEmpty(Issuer)) str += "Issuer: " + Issuer;
            if (!string.IsNullOrEmpty(Destination)) str += ", Destination: " + Destination;
            if (!string.IsNullOrEmpty(AssertionConsumerServiceURL)) str += ", AssertionConsumerServiceURL: " + AssertionConsumerServiceURL;
            if (!string.IsNullOrEmpty(ProviderName)) str += ", ProviderName: " + ProviderName;
            str += ")";
            return str;
        }
    }
}
