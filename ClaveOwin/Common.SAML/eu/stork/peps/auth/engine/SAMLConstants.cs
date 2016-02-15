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
    public static class SAMLConstants
    {
        // if null, 'urn:oasis:names:tc:SAML:2.0:nameid' is assumed.
        public const string ThisIssuerFormat = null;

        public const bool XML_XSD_VALIDATE = true;

        public static class ErrorCodes
        {
            public const int VALID = 0;
            public const int INVALID_CERTIFICATE = -1;
            public const int INVALID_SIGNATURE = -2;
            public const int NULL_XML = -3;
            public const int XML_VALIDATION_FAILED = -4;
            public const int INVALID_ATTRIBUTES = -5;
            public const int INVALID_DESTINATION = -6;
            public const int REPEATED_ID = -7;
            public const int UNKNOWN_ISSUER = -8;
            public const int EXPIRED = -9;
            public const int EXPIRED_ASSERTION = -10;

            public static string GetErrorDescription(int errorCode)
            {
                switch (errorCode)
                {
                    case VALID:
                        return "Valid request.";
                    case REPEATED_ID:
                        return StatusDetail.REPEATED_ID;
                    case EXPIRED_ASSERTION:
                        return StatusDetail.EXPIRED_ASSERTION;
                    case EXPIRED:
                        return StatusDetail.EXPIRED;
                    case UNKNOWN_ISSUER:
                        return StatusDetail.UNKNOWN_ISSUER;
                    case INVALID_CERTIFICATE:
                        return StatusDetail.INVALID_CERTIFICATE;
                    case INVALID_SIGNATURE:
                        return StatusDetail.INVALID_SIGNATURE;
                    case NULL_XML:
                    case XML_VALIDATION_FAILED:
                        return StatusDetail.INVALID_REQUEST;
                    case INVALID_DESTINATION:
                        return StatusDetail.INVALID_DESTINATION;
                    case INVALID_ATTRIBUTES:
                        return "Invalid attribute name or value.";
                    default: return "Unspecified.";
                }
            }
        }

        public static class AttributeStatus
        {
            public const int AVAILABLE = 0;
            public const int NOT_AVAILABLE = 1;
            public const int WITHHELD = 2;

            internal static readonly string[] attributeStatus = { "Available", "NotAvailable", "Withheld" };

            public static int GetAttrStatusFromDesc(string desc)
            {
                return Array.IndexOf(attributeStatus, desc);
            }
        }

        public static class StatusCode
        {
            public const int SUCCESS = 0;
            public const int REQUESTER = 1;
            public const int RESPONDER = 2;
            public const int AUTHN_FAILED = 3;
            public const int INVALID_ATTR_NAME_OR_VALUE = 4;
            public const int INVALID_NAME_ID_POLICY = 5;
            public const int REQUEST_DENIED = 6;

            internal static readonly string[] statusCode= {
                "urn:oasis:names:tc:SAML:2.0:status:Success",
                "urn:oasis:names:tc:SAML:2.0:status:Requester", 
                "urn:oasis:names:tc:SAML:2.0:status:Responder",
                "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
                "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue",
                "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
                "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
                                                          };

            public static int GetStatusCodeFromDesc(string desc)
            {
                return Array.IndexOf(statusCode, desc);
            }
        }

        public static class StatusMessage
        {
            public const string REQUESTER = "The request could not be performed due to an error on the " + 
                "SAML requester side (SP)";
            public const string RESPONDER = "The request could not be performed due to an error on the " +
                "SAML responder side (IdP)";
            public const string AUTHN_FAILED = "It was unable to successfully authenticate the citizen";
            public const string INVALID_ATTR_NAME_OR_VALUE = "Unexpected or invalid content was encountered " +
                "within a 'saml:Attribute' or 'saml:AttributeValue' element";
            public const string INVALID_NAME_ID_POLICY = "The requested name identifier policy is not supported.";
            public const string REQUEST_DENIED = "The request has not been processed";
        }

        public static class StatusDetail
        {
            public const string INVALID_CERTIFICATE = "Invalid Certificate";
            public const string INVALID_SIGNATURE = "Invalid Signature";
            public const string INVALID_REQUEST = "Invalid SAML Request";
            public const string INVALID_DESTINATION = "Invalid Destination";
            public const string USER_CANCEL = "User has canceled the process of obtaining attributes";
            public const string INTERNAL_ERROR = "An internal error has ocurred";
            public const string UNKNOWN_ISSUER = "The issuer is unknown";
            public const string REPEATED_ID = "SAML Request ID repeated";
            public const string EXPIRED = "SAML message is expired";
            public const string EXPIRED_ASSERTION = "SAML assertion has expired";
            public const string NO_CERTIFICATES = "No personal certificates have been found";
        }

        internal const string SAML_VERSION = "2.0";
        internal const string ATTRIBUTE_STATUS_STR = "AttributeStatus";

        /// <summary>
        /// The XML namespaces of the SAML 2.0 used schemas
        /// </summary>
        public const string NS_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
        public const string NS_ASSERT = "urn:oasis:names:tc:SAML:2.0:assertion";
        public const string NS_METADATA = "urn:oasis:names:tc:SAML:2.0:metadata";
        public const string NS_STORK_ASSER = "urn:eu:stork:names:tc:STORK:1.0:assertion";
        public const string NS_STORK_PROT = "urn:eu:stork:names:tc:STORK:1.0:protocol";

        public const string NS_PROTOCOL_PREFIX = "saml2p";
        public const string NS_ASSERT_PREFIX = "saml2";

        public const string NS_STORK_ASSER_PREFIX = "stork";
        public const string NS_STORK_PROT_PREFIX = "storkp";

        public const string CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:unspecified";
        public const string PROTOCOL_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
        public const string ATTRIBUTE_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    }
}
