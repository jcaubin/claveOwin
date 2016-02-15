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
using System.Text;

using eu.stork.peps.auth.commons;

//
// author: AMA – Agência para a Modernização Administrativa IP, PORTUGAL (www.ama.pt)
//
namespace eu.stork.peps.auth.engine
{
    public class SAMLContext
    {
        private Dictionary<string, AttributeElement> attributes = new Dictionary<string, AttributeElement>();

        internal SAMLContext(int errorCode)
        {
            ErrorCode = errorCode;
        }

        internal SAMLContext(int errorCode, string requestId, string assertionConsumer)
        {
            ErrorCode = errorCode;
            RequestID = requestId;
            AssertionConsumer = assertionConsumer;
        }

        public List<string> GetAttributeNames()
        {
            return new List<string>(attributes.Keys);
        }

        public List<string> GetAvailableAttribuetIds()
        {
            List<string> list = new List<string>(attributes.Keys);
            list.RemoveAll(delegate(string name)
                {
                    if (attributes[name].AttrStatus != SAMLConstants.AttributeStatus.AVAILABLE)
                        return true;
                    return false;
                });
            return list;
        }

        public bool IsAttributeRequired(string attrName)
        {
            return attributes[attrName].IsRequired;
        }

        public Object GetAttributeValue(string attrName)
        {
            return attributes[attrName].AttrValue;
        }

        public int GetAttributeStatus(string attrName)
        {
            return attributes[attrName].AttrStatus;
        }

        public bool SetAttribute(string attrName, string attrValue, int attrStatus)
        {
            AttributeElement attr = attributes[attrName];
            if (attr == null)
                return false;
            attr.AttrValue = attrValue;
            attr.AttrStatus = attrStatus;
            return true;
        }

        public bool SetAttributeValue(string attrName, string attrValue)
        {
            AttributeElement attr = attributes[attrName];
            if (attr == null)
                return false;
            attr.AttrValue = attrValue;
            return true;
        }

        public bool SetAttribute(string attrName, int attrStatus)
        {
            AttributeElement attr = attributes[attrName];
            if (attr == null)
                return false;
            attr.AttrStatus = attrStatus;
            return true;
        }

        internal void AddAttribute(string attrName, bool isRequired)
        {
            attributes.Add(attrName, new AttributeElement(attrName, isRequired));
        }

        internal List<AttributeElement> GetAttributes()
        {
            return new List<AttributeElement>(attributes.Values);
        }

        public int ErrorCode
        {
            get;
            internal set;
        }

        public int StatusCode
        {
            get;
            set;
        }

        public int SubStatusCode
        {
            get;
            set;
        }

        public string StatusCodeStr
        {
            get { return SAMLConstants.StatusCode.statusCode[StatusCode]; }
        }

        public string StatusMessage
        {
            get;
            set;
        }

        public string Issuer
        {
            get;
            internal set;
        }

        public string RequestID
        {
            get;
            internal set;
        }

        public string AssertionConsumer
        {
            get;
            internal set;
        }

        public string SubjectAddress
        {
            get;
            set;
        }

        /// <summary>
        /// GEt general information about the SAML Context
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            String str = "SAMLContext(" + Environment.NewLine;
            str += " ErrorCode: " + ErrorCode;
            if (ErrorCode != 0)
            {
                str += " (" + SAMLConstants.ErrorCodes.GetErrorDescription(ErrorCode) + ")";
            }
            str += Environment.NewLine;
            if (!string.IsNullOrEmpty(Issuer)) str += " Issuer: " + Issuer + Environment.NewLine;
            if (!string.IsNullOrEmpty(RequestID)) str += " RequestID: " + RequestID + Environment.NewLine;
            if (!string.IsNullOrEmpty(AssertionConsumer)) str += " AssertionConsumer: " + AssertionConsumer + Environment.NewLine;
            if (!string.IsNullOrEmpty(SubjectAddress)) str += " SubjectAddress: " + SubjectAddress + Environment.NewLine;
            if (!string.IsNullOrEmpty(StatusCodeStr)) str += " Code: " + StatusCodeStr + Environment.NewLine;
            if (SubStatusCode != 0)
            {
                str += " SubCode: " + SAMLConstants.StatusCode.statusCode[SubStatusCode] + Environment.NewLine;
            }
            if (!string.IsNullOrEmpty(StatusMessage)) str += " Message: " + StatusMessage + Environment.NewLine;
            str += ")";
            return str;
        }

    }
}
