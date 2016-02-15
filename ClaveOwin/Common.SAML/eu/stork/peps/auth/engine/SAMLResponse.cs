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
    public class SAMLResponse
    {
        private Dictionary<string, AttributeElement> attributes = new Dictionary<string, AttributeElement>();

        public SAMLResponse()
        {
        }

        public SAMLResponse(int errorCode) 
        {
            ErrorCode = errorCode;
        }

        public List<string> GetAttributeNames()
        {
            return new List<string>(attributes.Keys);
        }

        public bool isAttributeComplex(string attrName)
        {
            return attributes[attrName].AttrHasComplexValue;
        }

        public Dictionary<string, string> GetAttributeComplexValue(string attrName)
        {
            if (!attributes.ContainsKey(attrName))
                return null;
            return attributes[attrName].AttrComplexValue;
        }

        public bool isAttributeSimple(string attrName)
        {
            return attributes[attrName].AttrHasSimpleValue;
        }

        public string GetAttributeValue(string attrName)
        {
            if (!attributes.ContainsKey(attrName))
                return null;
            return attributes[attrName].AttrValue;
        }

        public int GetAttributeStatus(string attrName)
        {
            if (!attributes.ContainsKey(attrName))
                return -1;
            return attributes[attrName].AttrStatus;
        }

        public string GetAttributeStatusStr(string attrName)
        {
            if (!attributes.ContainsKey(attrName))
                return null;
            return attributes[attrName].Status;
        }

        public void AddAttributeTesting(string attrName, string attrValue, int attrStatus)
        {
            attributes.Add(attrName, new AttributeElement(attrName, attrValue, attrStatus));
        }

        
        internal void AddAttribute(string attrName, Dictionary<string, string> attrValue, int attrStatus)
        {
            attributes.Add(attrName, new AttributeElement(attrName, attrValue, attrStatus));

        }

        internal void AddAttribute(string attrName, string attrValue, int attrStatus)
        {
            attributes.Add(attrName, new AttributeElement(attrName, attrValue, attrStatus));
        }

        public int ErrorCode
        {
            get;
            internal set;
        }

        public string InResponseTo
        {
            get;
            internal set;
        }

        public string QAALevel {
            get;
            internal set;
        }

        public string Idp {
            get;
            internal set;
        }
        
        public int StatusCode
        {
            get;
            internal set;
        }

        public int SubStatusCode
        {
            get;
            internal set;
        }

        public string StatusCodeStr
        {
            get { return SAMLConstants.StatusCode.statusCode[StatusCode]; }
        }

        public string SubStatusCodeStr
        {
            get { return SAMLConstants.StatusCode.statusCode[SubStatusCode]; }
        }

        public string StatusMessage
        {
            get;
            internal set;
        }

        public override string ToString()
        {
            String str = "SAMLResponse(ErrorCode: " + ErrorCode;
            str += ", StatusCode: " + StatusCodeStr;
            if (!string.IsNullOrEmpty(StatusMessage)) str += ", StatusMessage: " + StatusMessage;
            str += ")";
            return str;
        }
    }
}
