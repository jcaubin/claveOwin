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
using System.Xml;

//
// author: AMA – Agência para a Modernização Administrativa IP, PORTUGAL (www.ama.pt)
//
namespace eu.stork.peps.auth.engine
{
    public interface ISAMLEngine
    {        
        void Init(string path);

        // client side
        XmlDocument GenerateRequest(SAMLRequest request);
        SAMLResponse HandleResponse(XmlDocument xmlResponse);

        // server side
        SAMLContext HandleRequest(XmlDocument xmlRequest);
        XmlDocument GenerateResponse(SAMLContext context);
    }
}
