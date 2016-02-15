﻿using eu.stork.peps.auth.commons;
using eu.stork.peps.auth.engine;
using Kentor.AuthServices.WebSso;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace eu.stork.peps.auth.Service
{
    public class SamlService
    {
        public string SamlLoginUrl { get { return ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SEND_TO); } }

        public string SamlLogoutUrl { get { return ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.LOGOUT_SEND_TO); } }

        public string GetSamLoginRequest(string reqPath)
        {
            try
            {
                SAMLRequest request = new SAMLRequest();
                request.Destination = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SPEPS);
                request.AssertionConsumerServiceURL = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SP_RETURN_URL)+"?reqPath="+reqPath;
                request.Alias = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.CPEPS);
                request.ProviderName = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.PROVIDERNAME);
                request.Issuer = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SAMLISSUER);
                request.QAALevel = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.QAALEVEL);
                request.Id = "_" + Guid.NewGuid().ToString();

                request.AddAttribute("eIdentifier", true);
                request.AddAttribute("givenName", true);
                request.AddAttribute("surname", true);
                request.AddAttribute("inheritedFamilyName", false);
                request.AddAttribute("eMail", false);

                SAMLEngine samlEngine = SAMLEngine.Instance;
                samlEngine.Init();
                XmlDocument xml = samlEngine.GenerateRequest(request);
                string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(xml.OuterXml));
                return b64;
            }
            catch (Exception)
            {
                throw;
            }
        }

        public string GetSamlLogoutRequest()
        {
            try
            {
                SAMLLogoutRequest request = new SAMLLogoutRequest();

                request.Destination = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.LOGOUT_SEND_TO);
                request.Alias = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.CPEPS);
                request.Issuer = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SP_LOGOUT_RETURN_URL);
                request.QAALevel = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.QAALEVEL);
                request.Id = "_" + Guid.NewGuid().ToString();
                request.Country = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SAMLCOUNTRY);
                request.SpProvidedId = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.PROVIDERNAME);
                request.NameID = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SP_ID);

                SAMLEngine samlEngine = SAMLEngine.Instance;
                samlEngine.Init();
                XmlDocument xml = samlEngine.GenerateLogoutRequest(request);
                string base64String = Convert.ToBase64String(Encoding.UTF8.GetBytes(xml.OuterXml));
                return base64String;
            }
            catch (Exception)
            {
                throw;
            }
        }

        public SAMLResponse ProcessSamlLoginResponse(string b64response)
        {
            try
            {
                byte[] reqDataB64 = Convert.FromBase64String(b64response);
                string reqData = Encoding.UTF8.GetString(reqDataB64);
                XmlDocument xml = new XmlDocument();
                xml.PreserveWhitespace = true;
                xml.LoadXml(reqData);

                SAMLEngine.Instance.Init();
                SAMLResponse sr = SAMLEngine.Instance.HandleResponse(xml);
                return sr;
            }
            catch (Exception e)
            {
                SAMLResponse sr = new SAMLResponse();
                sr.ErrorCode = -11;
                sr.StatusCode = SAMLConstants.StatusCode.AUTHN_FAILED;
                sr.StatusMessage = e.Message;
                return sr;
            }
        }

        public SamlPersonalData GetPersonalData(SAMLResponse sr)
        {
            var eIdentifierAn = sr.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("eIdentifier" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
            var GivenNameAn = sr.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("givenName" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
            var SurnameAn = sr.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("surname" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
            var InheritedFamilyNameAN = sr.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("inheritedFamilyName" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
            var EmailAn = sr.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("eMail" + CommonConstants.ATTRIBUTE_NS_SUFFIX));

            var spd = new SamlPersonalData();
            spd.eIdentifier = sr.isAttributeSimple(eIdentifierAn) ? sr.GetAttributeValue(eIdentifierAn) : sr.GetAttributeComplexValue(eIdentifierAn).Select(m => m.Value).FirstOrDefault();
            spd.GivenName = sr.isAttributeSimple(GivenNameAn) ? sr.GetAttributeValue(GivenNameAn) : sr.GetAttributeComplexValue(GivenNameAn).Select(m => m.Value).FirstOrDefault();
            spd.Surname = sr.isAttributeSimple(SurnameAn) ? sr.GetAttributeValue(SurnameAn) : sr.GetAttributeComplexValue(SurnameAn).Select(m => m.Value).FirstOrDefault();
            spd.InheritedFamilyName = sr.isAttributeSimple(InheritedFamilyNameAN) ? sr.GetAttributeValue(InheritedFamilyNameAN) : sr.GetAttributeComplexValue(InheritedFamilyNameAN).Select(m => m.Value).FirstOrDefault();
            spd.Email = sr.isAttributeSimple(EmailAn) ? sr.GetAttributeValue(EmailAn) : sr.GetAttributeComplexValue(EmailAn).Select(m => m.Value).FirstOrDefault();
            return spd;
        }

        public SAMLLogoutResponse ProcessSamlLogoutResponse(string b64response)
        {
            try
            {
                byte[] reqDataB64 = Convert.FromBase64String(b64response);
                string reqData = Encoding.UTF8.GetString(reqDataB64);

                XmlDocument xml = new XmlDocument();
                xml.PreserveWhitespace = true;
                xml.LoadXml(reqData);

                SAMLEngine.Instance.Init();
                SAMLLogoutResponse samlLogoutResponse = SAMLEngine.Instance.HandleLogoutResponse(xml);
                return samlLogoutResponse;
            }
            catch (Exception e)
            {
                SAMLLogoutResponse sr = new SAMLLogoutResponse();
                sr.ErrorCode = -11;
                sr.StatusCode = SAMLConstants.StatusCode.AUTHN_FAILED;
                sr.StatusMessage = e.Message;
                return sr;
            }
        }

        public string GetSamlPostLoginRequest(string reqPath)
        {
            string sendTo = SamlLoginUrl;
            string SAMLRequest = GetSamLoginRequest(reqPath);
            string excludedIdpList = "none";
            string forcedIdP = "none";

            var postHtml = string.Format(htmlPostString, sendTo, excludedIdpList, forcedIdP, SAMLRequest);
            return postHtml;
        }
        
        public CommandResult GetSamlCommandResult(string reqPath)
        {
            CommandResult cr = new CommandResult()
            {
                Content = GetSamlPostLoginRequest(reqPath),
                ContentType = "text/html"
            };
            return cr;
        }

        public CommandResult GetSamlResponseCommandResult(HttpRequestData request)
        {
            CommandResult cr = new CommandResult();
            var sr = (string)request.Form["SAMLResponse"];
            var spr = ProcessSamlLoginResponse(sr);

            cr.HttpStatusCode = System.Net.HttpStatusCode.Redirect;
            ClaimsIdentity cidt = new ClaimsIdentity(DefaultAuthenticationTypes.ExternalCookie);

            var eIdentifierAn = spr.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("eIdentifier" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
            var GivenNameAn = spr.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("givenName" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
            var SurnameAn = spr.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("surname" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
            var InheritedFamilyNameAN = spr.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("inheritedFamilyName" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
            var EmailAn = spr.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("eMail" + CommonConstants.ATTRIBUTE_NS_SUFFIX));

            var eIdentifier = spr.isAttributeSimple(eIdentifierAn) ? spr.GetAttributeValue(eIdentifierAn) : spr.GetAttributeComplexValue(eIdentifierAn).Select(m => m.Value).FirstOrDefault();
            var GivenName = spr.isAttributeSimple(GivenNameAn) ? spr.GetAttributeValue(GivenNameAn) : spr.GetAttributeComplexValue(GivenNameAn).Select(m => m.Value).FirstOrDefault();
            var Surname = spr.isAttributeSimple(SurnameAn) ? spr.GetAttributeValue(SurnameAn) : spr.GetAttributeComplexValue(SurnameAn).Select(m => m.Value).FirstOrDefault();
            var InheritedFamilyName = spr.isAttributeSimple(InheritedFamilyNameAN) ? spr.GetAttributeValue(InheritedFamilyNameAN) : spr.GetAttributeComplexValue(InheritedFamilyNameAN).Select(m => m.Value).FirstOrDefault();
            var Email = spr.isAttributeSimple(EmailAn) ? spr.GetAttributeValue(EmailAn) : spr.GetAttributeComplexValue(EmailAn).Select(m => m.Value).FirstOrDefault();



            cidt.AddClaim(new Claim(ClaimTypes.NameIdentifier, eIdentifier, ClaimValueTypes.String, "CLAVE"));
            cidt.AddClaim(new Claim(eIdentifierAn,eIdentifier, ClaimValueTypes.String, "CLAVE"));
            cidt.AddClaim(new Claim(ClaimTypes.GivenName, GivenName, ClaimValueTypes.String, "CLAVE"));
            cidt.AddClaim(new Claim(ClaimTypes.Surname, Surname, ClaimValueTypes.String, "CLAVE"));
            cidt.AddClaim(new Claim(InheritedFamilyNameAN, InheritedFamilyName, ClaimValueTypes.String, "CLAVE"));
            cidt.AddClaim(new Claim(ClaimTypes.Email, Email, ClaimValueTypes.Email, "CLAVE"));

            

            ClaimsPrincipal cp = new ClaimsPrincipal(new ClaimsIdentity[] { cidt });
            cr.Principal = cp;
            return cr;
        }


        private const string htmlPostString = @"
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body  onload=""document.forms[0].submit()""> 
    <div> 
       <form action=""{0}"" method=""post"">
            <fieldset>
                <legend>Acceso con cl@ve</legend>
				
				<input type=""hidden"" name=""excludedIdpList"" value=""{1}""/>
				<input type=""hidden"" name=""forcedIdP"" value=""{2}""/>
				<input type=""hidden"" name=""SAMLRequest"" value=""{3}""/>			
     
                <input type=""submit"" value=""acceder"" />
            </fieldset>
       </form>
    </div>
</body>
</html>";
    }
}