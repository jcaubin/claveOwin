﻿/*
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

using eu.stork.peps.auth.commons;

//
// author: AMA – Agência para a Modernização Administrativa IP, PORTUGAL (www.ama.pt)
//
namespace eu.stork.peps.auth.engine
{
    internal class AttributeElement
    {

        public AttributeElement(string attrName, string attrValue, int attrStatus)
        {
            AttrName = attrName;
            AttrValue = attrValue;
            AttrStatus = attrStatus;
            AttrHasSimpleValue = true;
        }

        public AttributeElement(string attrName, Dictionary<string, string> attrValues, int attrStatus)
        {
            AttrName = attrName;
            AttrComplexValue = attrValues;
            AttrStatus = attrStatus;
            AttrHasComplexValue = true;
        }

        public AttributeElement(string attrName, bool isRequired)
        {
            AttrName = attrName;
            IsRequired = isRequired;
            AttrStatus = -1;
        }

        public bool IsRequired
        {
            get;
            set;
        }

        public string AttrValue
        {
            get;
            set;
        }

        public Dictionary<string, string> AttrComplexValue
        {
            get;
            set;
        }

        public int AttrStatus
        {
            get;
            set;
        }

        public string AttrName
        {
            get;
            set;
        }

        public string NameFormat
        {
            get { return SAMLConstants.ATTRIBUTE_NAME_FORMAT; }
        }

        public string Status
        {
            get { return AttrStatus < 0 ? null : 
                SAMLConstants.AttributeStatus.attributeStatus[AttrStatus]; }
        }

        public bool AttrHasSimpleValue { get; set; }

        public bool AttrHasComplexValue { get; set; }
    }
}
