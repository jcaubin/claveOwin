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
using System.Data;

using System.Configuration;

//
// author: AMA – Agência para a Modernização Administrativa IP, PORTUGAL (www.ama.pt)
//
namespace eu.stork.peps.auth.commons
{
    public class CitizenAttributes
    {
        private static readonly CitizenAttributes instance = new CitizenAttributes();

        private Dictionary<string, Attribute> personalAttributes;

        private Dictionary<string, Attribute> businessAttributes;

        private Dictionary<string, Attribute> legalAttributes;

        private CitizenAttributes()
        {
            PopulatePEPSAttributes();
            return;
        }

        private void PopulatePEPSAttributes()
        {
            /* Personal attributes */
            char[] attrListSep = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.ATTRIBUTE_SEP).ToCharArray();
            string[] attrList = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.PERSONAL_ATTRIBUTE_LIST).Split(attrListSep);

            personalAttributes = new Dictionary<string, Attribute>(attrList.Length);
            string now = DateTime.Now.ToString();
            foreach (string attr in attrList)
            {
                string attrNS = ConfigurationSettingsHelper.GetCriticalConfigSetting(attr+CommonConstants.ATTRIBUTE_NS_SUFFIX);
                Attribute attribute = new Attribute(attrNS, attr,
                    attr, true, -1, 0, now);
                personalAttributes.Add(attrNS, attribute);
            }
            /* Business attributes */
            string[] businessAttrList = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.BUSINESS_ATTRIBUTE_LIST).Split(attrListSep); 
            
            businessAttributes = new Dictionary<string, Attribute>(businessAttrList.Length);
            now = DateTime.Now.ToString();
            foreach (string attr in businessAttrList) {
                string attrNS = ConfigurationSettingsHelper.GetCriticalConfigSetting(attr + CommonConstants.ATTRIBUTE_NS_SUFFIX);
                Attribute attribute = new Attribute(attrNS, attr,
                    attr, true, -1, 0, now);
                businessAttributes.Add(attrNS, attribute);
            }
            /* Legal attributes */
            string[] legalAttrList = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.LEGAL_ATTRIBUTE_LIST).Split(attrListSep);
            
            legalAttributes = new Dictionary<string, Attribute>(legalAttrList.Length);
            now = DateTime.Now.ToString();
            foreach (string attr in legalAttrList) {
                string attrNS = ConfigurationSettingsHelper.GetCriticalConfigSetting(attr + CommonConstants.ATTRIBUTE_NS_SUFFIX);
                Attribute attribute = new Attribute(attrNS, attr,
                    attr, true, -1, 0, now);
                legalAttributes.Add(attrNS, attribute);
            }
        }

        public static CitizenAttributes Instance
        {
            get { return instance; }
        }

        public Boolean Exists(string name) {
            if (personalAttributes.ContainsKey(name) || businessAttributes.ContainsKey(name) || legalAttributes.ContainsKey(name)) {
                return true;
            } else {
                return false;
            }
        }

        public List<string> GetPersonalNames() {
            return new List<string>(personalAttributes.Keys);
        }

        public List<string> GetBusinessNames() {
            return new List<string>(businessAttributes.Keys);
        }
        
        public List<string> GetLegalNames() {
            return new List<string>(legalAttributes.Keys);
        }

        public string GetFriendlyName(string name)
        {
            if (personalAttributes.ContainsKey(name))
                return personalAttributes[name].FriendlyName;
            if (businessAttributes.ContainsKey(name))
                return businessAttributes[name].FriendlyName;
            if (legalAttributes.ContainsKey(name))
                return legalAttributes[name].FriendlyName;
            return "none";
        }

        public string GetDescription(string name)
        {
            if (personalAttributes.ContainsKey(name))
                return personalAttributes[name].Description;
            if (businessAttributes.ContainsKey(name))
                return businessAttributes[name].Description;
            if (legalAttributes.ContainsKey(name))
                return legalAttributes[name].Description;
            return "none";
        }

        public bool HasValueVisualization(string name)
        {
            if (personalAttributes.ContainsKey(name))
                return personalAttributes[name].HasValueVisualization;
            if (businessAttributes.ContainsKey(name))
                return businessAttributes[name].HasValueVisualization;
            if (legalAttributes.ContainsKey(name))
                return legalAttributes[name].HasValueVisualization;
            return false;
        }

        public int GetProviderId(string name)
        {
            if (personalAttributes.ContainsKey(name))
                return personalAttributes[name].AttributeProviderId;
            if (businessAttributes.ContainsKey(name))
                return businessAttributes[name].AttributeProviderId;
            if (legalAttributes.ContainsKey(name))
                return legalAttributes[name].AttributeProviderId;
            return -1;
        }

        public int GetOrderIndex(string name)
        {
            if (personalAttributes.ContainsKey(name))
                return personalAttributes[name].OrderIndex;
            if (businessAttributes.ContainsKey(name))
                return businessAttributes[name].OrderIndex;
            if (legalAttributes.ContainsKey(name))
                return legalAttributes[name].OrderIndex;
            return -1;
        }

        public string GetLastUpdate(string name)
        {
            if (personalAttributes.ContainsKey(name))
                return personalAttributes[name].LastUpdate;
            if (businessAttributes.ContainsKey(name))
                return businessAttributes[name].LastUpdate;
            if (legalAttributes.ContainsKey(name))
                return legalAttributes[name].LastUpdate;
            return "none";
        }

        private class Attribute
        {
            public Attribute(string name, string friendlyName, string description,
                bool hasValueVisualization, int attrProviderId, int orderIndex, 
                string lastUpdate)
            {
                Name = name;
                FriendlyName = friendlyName;
                Description = description;
                HasValueVisualization = hasValueVisualization;
                AttributeProviderId = attrProviderId;
                OrderIndex = orderIndex;
                LastUpdate = lastUpdate;
            }

            public string Name
            {
                get;
                set;
            }
            public string FriendlyName
            {
                get;
                set;
            }
            public string Description
            {
                get;
                set;
            }
            public bool HasValueVisualization
            {
                get;
                set;
            }
            public int AttributeProviderId
            {
                get;
                set;
            }
            public int OrderIndex
            {
                get;
                set;
            }
            public string LastUpdate
            {
                get;
                set;
            }
            public int SerialNumber
            {
                get;
                set;
            }
        }
    }
}
