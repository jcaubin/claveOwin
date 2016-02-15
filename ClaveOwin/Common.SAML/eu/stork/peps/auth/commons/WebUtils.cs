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
using System.Web;
using System.Text;
using System.Collections.Generic;

//
// author: AMA – Agência para a Modernização Administrativa IP, PORTUGAL (www.ama.pt)
//
namespace eu.stork.peps.auth.commons
{
    public static class WebUtils
    {
        public static string PreparePOSTForm(string url, string samlField,
            string relayStateField, string samlRequest, string relayState, bool clearSslState)
        {
            string formID = "PostForm", str = string.Empty;
            str += "<form id='" + formID + "' name='" + formID + "' action='" + url + "' method='POST'>";
            str += "<input type='hidden' name='" + samlField + "' value='" + samlRequest + "' />";
            str += "<input type='hidden' name='" + relayStateField + "' value='" + relayState + "' />";
            str += "</form>";
            str += "<script language='javascript'>";
            if (clearSslState)
                str += "try { document.execCommand('ClearAuthenticationCache'); } catch(err) {}";
            str += "var v" + formID + " = document." + formID + ";";
            str += "v" + formID + ".submit();";
            str += "</script>";
            return str;
        }

        public static string PreparePOSTForm(string samlField, string relayStateField,
            string countryField, string samlRequest, string relayState, string spepsCountry, string cpepsCountry, string legalperson)
        {
            string spepsCountryURL = ConfigurationSettingsHelper.GetCriticalConfigSetting(spepsCountry+CommonConstants.SPEPS_SUFFIX);

            string formID = "PostForm", str = string.Empty;
            str += "<form id='" + formID + "' name='" + formID + "' action='" + spepsCountryURL + "' method='POST'>";
            str += "<input type='hidden' name='" + samlField + "' value='" + samlRequest + "' />";
            str += "<input type='hidden' name='" + relayStateField + "' value='" + relayState + "' />";
            str += "<input type='hidden' name='" + countryField + "' value='" + cpepsCountry + "' />";
            str += "<input type='hidden' name='allowLegalPerson' id='allowLegalPerson' value='" + legalperson + "' />;";
            str += "<input type='hidden' name='mostrarA' value='true' />";
            str += "</form>";
            str += "<script language='javascript'>";
            str += "var v" + formID + " = document." + formID + ";";
            str += "v" + formID + ".submit();";
            str += "</script>";
            return str;
        }

        public static string PreparePOSTForm(string samlField, string relayStateField,
            string countryField, string samlRequest, string relayState, string spepsCountry, string cpepsCountry, List<string> idpList, String force, String legalperson)
        {
            string spepsCountryURL = ConfigurationSettingsHelper.GetCriticalConfigSetting(spepsCountry + CommonConstants.SPEPS_SUFFIX);

            string formID = "PostForm", str = string.Empty;
            str += "<form id='" + formID + "' name='" + formID + "' action='" + spepsCountryURL + "' method='POST'>";
            str += "<input type='hidden' name='" + samlField + "' value='" + samlRequest + "' />";
            str += "<input type='hidden' name='" + relayStateField + "' value='" + relayState + "' />";
            str += "<input type='hidden' name='" + countryField + "' value='" + cpepsCountry + "' />";
            str += "<input type='hidden' name='allowLegalPerson' id='allowLegalPerson' value='" + legalperson + "' />;";
            str += "<input type='hidden' name='excludedIdPList' value='";
            foreach (string entry in idpList) {
                str += entry.ToString() + ";";
            }
            str += "' id='excludedIdPList'/>";
            str += "<input type='hidden' name='forcedIdP' value='"+force+"' id='forcedIdP'/>";
            str += "</form>";
            str += "<script language='javascript'>";
            str += "var v" + formID + " = document." + formID + ";";
            str += "v" + formID + ".submit();";
            str += "</script>";
            return str;
        }

        /// <summary>
        /// Sets No Chache to Cliente browser
        /// </summary>
        /// <param name="response"></param>
        public static void SetNoCacheNoStore(HttpResponse response)
        {
            response.ClearHeaders();
            response.AppendHeader("Cache-Control", "no-cache"); //HTTP 1.1
            response.AppendHeader("Cache-Control", "private"); // HTTP 1.1
            response.AppendHeader("Cache-Control", "no-store"); // HTTP 1.1
            response.AppendHeader("Cache-Control", "must-revalidate"); // HTTP 1.1
            response.AppendHeader("Cache-Control", "max-stale=0"); // HTTP 1.1 
            response.AppendHeader("Cache-Control", "post-check=0"); // HTTP 1.1 
            response.AppendHeader("Cache-Control", "pre-check=0"); // HTTP 1.1 
            response.AppendHeader("Pragma", "no-cache"); // HTTP 1.1 
            response.AppendHeader("Keep-Alive", "timeout=3, max=993"); // HTTP 1.1 
            response.AppendHeader("Expires", "Mon, 26 Jul 1997 05:00:00 GMT"); // HTTP 1.1 

            response.Cache.SetExpires(DateTime.UtcNow.AddMinutes(-1));
            response.Cache.SetCacheability(HttpCacheability.Private);
            response.Cache.SetNoStore();
        }

        public static string GetIP(HttpRequest request)
        {
            return request.ServerVariables["REMOTE_ADDR"];
        }

        private const string STR_PostForm = "PostForm";

        public static string PrepareErrorPOSTForm(string url, string samlField,
            string relayStateField, string samlRequest, string relayState, bool clearSslState)
        {
            string formID = "PostForm", str = string.Empty;
            str += "<form id='" + formID + "' name='" + formID + "' action='" + url + "' method='POST'>";
            str += "<input type='hidden' name='" + samlField + "' value='" + samlRequest + "' />";
            str += "<input type='hidden' name='" + relayStateField + "' value='" + relayState + "' />";
            str += "</form>";
            str += "<script language='javascript'>";
            if (clearSslState)
                str += "try { document.execCommand('ClearAuthenticationCache'); } catch(err) {}";
            str += "var v" + formID + " = document." + formID + ";";
            str += "v" + formID + ".submit();";
            str += "</script>";
            return str;
        }
    }
}
