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
    public class SAMLLogoutResponse
    {
        
        public SAMLLogoutResponse()
        {
        }

        public SAMLLogoutResponse(int errorCode)
        {
            ErrorCode = errorCode;
        }

        public string InResponseTo
        {
            get;
            internal set;
        }

        public string issuer
        {
            get;
            internal set;
        }

        public string NameID
        {
            get;
            internal set;
        }

        public int ErrorCode
        {
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
