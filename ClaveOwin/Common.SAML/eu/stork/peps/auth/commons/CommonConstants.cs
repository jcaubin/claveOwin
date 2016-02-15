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
namespace eu.stork.peps.auth.commons
{
    public static class CommonConstants
    {
        public const string ATTRIBUTE_NS_SUFFIX     = ".NS";
        public const string PERSONAL_ATTRIBUTE_LIST = "PersonalAttributeList";
        public const string ATTRIBUTE_SEP           = "AttributeSeparator";
        public const string BUSINESS_ATTRIBUTE_LIST = "BusinessAttributeList";
        public const string COUNTRY_LIST_SUFFIX     = ".CountryList";
        public const string COUNTRY_SEP             = "CountrySeparator";
        public const string CPEPS                   = "CPEPS";
        public const string CPEPS_SUFFIX            = ".CPEPSURL";
        public const string LEGAL_ATTRIBUTE_LIST    = "LegalAttributeList";
        public const string NS_ATTRIBUTES_ATTR      = "NSAttributes";
        public const string NS_ATTRIBUTES_PREFIX    = "NSAttributesPrefix";
        public const string NS_QAALEVEL             = "NSQAALevel";
        public const string NS_QAALEVEL_PREFIX      = "NSQAALevelPrefix";
        public const string NS_REQ_ATTR             = "NSReqAttr";
        public const string NS_REQ_ATTR_PREFIX      = "NSReqAttrPrefix";
        public const string NS_REQ_ATTRS            = "NSReqAttrs";
        public const string NS_REQ_ATTRS_PREFIX     = "NSReqAttrsPrefix";
        public const string PROVIDERNAME            = "SPProviderName";
        public const string QAALEVEL                = "SPQAALevel";
        public const string SAMLAPPLICATION         = "SPApplication";
        public const string SAMLCOUNTRY             = "SPCountry";
        public const string SAMLINSTITUTION         = "SPInstitution";
        public const string SAMLISSUER              = "SPIssuer";
        public const string SAMLSECTOR              = "SPSector";
        public const string SPEPS_SUFFIX            = ".SPEPSURL";
        public const string SPEPS                   = "SPEPS";
        public const string SP_RETURN_URL           = "SPReturnURL";
        public const string SP_VC_FILE              = "SPVCFile";
        public const string SEND_TO                 = "SendTo";
        public const string LOGOUT_SEND_TO          = "LogoutSendTo";
        public const string SP_LOGOUT_RETURN_URL    = "SPLogoutReturnURL";
        public const string SP_ID                   = "SPID";
        public const string FORCE_AUTH              = "forceAuth";
    }
}
