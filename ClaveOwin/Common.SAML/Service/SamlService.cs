using eu.stork.peps.auth.commons;
using eu.stork.peps.auth.engine;
using Kentor.AuthServices.WebSso;
using Microsoft.AspNet.Identity;
using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using static eu.stork.peps.auth.engine.SAMLConstants;

namespace eu.stork.peps.auth.Service
{
    public class SamlService
    {
        private static Logger _logger = LogManager.GetCurrentClassLogger();

        private readonly string _issuer = "cl@ve";

        private string _samlLoginUrl = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SEND_TO); 

        private string _samlLogoutUrl = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.LOGOUT_SEND_TO); 

        /// <summary>
        /// Peticion de autenticacion SAML
        /// </summary>
        /// <param name="reqPath">ruta de retorno</param>
        /// <returns>Peticion SAML XML codificado en b64 </returns>
        public string GetSamLoginRequest(string reqPath)
        {
            try
            {
                SAMLRequest request = new SAMLRequest();
                request.Destination = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SPEPS);
                request.AssertionConsumerServiceURL = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SP_RETURN_URL) + "?reqPath=" + reqPath;
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
                _logger.Trace("Peticion SAML2: {0} ;", xml.OuterXml);
                string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(xml.OuterXml));
                return b64;
            }
            catch (Exception e)
            {
                _logger.Error(e);
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
                request.Country = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SAMLCOUNTRY);
                request.SpProvidedId = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.PROVIDERNAME);
                request.NameID = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SP_ID);
                request.Id = "_" + Guid.NewGuid().ToString();

                SAMLEngine samlEngine = SAMLEngine.Instance;
                samlEngine.Init();
                XmlDocument xml = samlEngine.GenerateLogoutRequest(request);
                string base64String = Convert.ToBase64String(Encoding.UTF8.GetBytes(xml.OuterXml));
                return base64String;
            }
            catch (Exception e)
            {
                _logger.Error(e);
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
                _logger.Error(e);
                SAMLResponse sr = new SAMLResponse();
                sr.ErrorCode = -11;
                sr.StatusCode = SAMLConstants.StatusCode.AUTHN_FAILED;
                sr.StatusMessage = e.Message;
                return sr;
            }
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
                _logger.Error(e);
                SAMLLogoutResponse sr = new SAMLLogoutResponse();
                sr.ErrorCode = -11;
                sr.StatusCode = SAMLConstants.StatusCode.AUTHN_FAILED;
                sr.StatusMessage = e.Message;
                return sr;
            }
        }

        /// <summary>
        /// Obtiene el comando de petición de autenticación
        /// </summary>
        /// <param name="reqPath">Ruta relativa de retorno</param>
        /// <returns>Comando de autenticacion: formulario para generar automaticamente la llamada POST a cl@ve </returns>
        public CommandResult GetSamlCommandResult(string reqPath)
        {
            try
            {
                //Peticion SAML b64
                string SAMLRequest = GetSamLoginRequest(reqPath);

                //Formulario de peticion enlace-POST
                string sendTo = _samlLoginUrl;
                string excludedIdpList = "none";
                string forcedIdP = "none";
                var postHtml = string.Format(htmlPostString, sendTo, excludedIdpList, forcedIdP, SAMLRequest);

                CommandResult cr = new CommandResult()
                {
                    Content = postHtml,
                    ContentType = "text/html"
                };
                return cr;
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw;
            }
        }

        /// <summary>
        /// Obtiene el comando de respuesta de autenticación
        /// </summary>
        /// <param name="request">Respuesta desde clave</param>
        /// <returns>Comando con la identidad reconocida en la autenticacion</returns>
        public CommandResult GetSamlResponseCommandResult(HttpRequestData request)
        {
            try
            {
                var samlResponse = ProcessSamlLoginResponse(request.Form["SAMLResponse"]);
                CommandResult commandResult = new CommandResult();
                if (samlResponse.StatusCode == StatusCode.SUCCESS)
                {
                    ClaimsIdentity cidt = new ClaimsIdentity(DefaultAuthenticationTypes.ExternalCookie);
                    var eIdentifierAn = samlResponse.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("eIdentifier" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
                    var GivenNameAn = samlResponse.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("givenName" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
                    var SurnameAn = samlResponse.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("surname" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
                    var InheritedFamilyNameAN = samlResponse.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("inheritedFamilyName" + CommonConstants.ATTRIBUTE_NS_SUFFIX));
                    var EmailAn = samlResponse.GetAttributeNames().SingleOrDefault(a => a == ConfigurationSettingsHelper.GetCriticalConfigSetting("eMail" + CommonConstants.ATTRIBUTE_NS_SUFFIX));

                    var eIdentifier = samlResponse.isAttributeSimple(eIdentifierAn) ? samlResponse.GetAttributeValue(eIdentifierAn) : samlResponse.GetAttributeComplexValue(eIdentifierAn).Select(m => m.Value).FirstOrDefault();
                    var GivenName = samlResponse.isAttributeSimple(GivenNameAn) ? samlResponse.GetAttributeValue(GivenNameAn) : samlResponse.GetAttributeComplexValue(GivenNameAn).Select(m => m.Value).FirstOrDefault();
                    var Surname = samlResponse.isAttributeSimple(SurnameAn) ? samlResponse.GetAttributeValue(SurnameAn) : samlResponse.GetAttributeComplexValue(SurnameAn).Select(m => m.Value).FirstOrDefault();
                    var InheritedFamilyName = samlResponse.isAttributeSimple(InheritedFamilyNameAN) ? samlResponse.GetAttributeValue(InheritedFamilyNameAN) : samlResponse.GetAttributeComplexValue(InheritedFamilyNameAN).Select(m => m.Value).FirstOrDefault();
                    var Email = samlResponse.isAttributeSimple(EmailAn) ? samlResponse.GetAttributeValue(EmailAn) : samlResponse.GetAttributeComplexValue(EmailAn).Select(m => m.Value).FirstOrDefault();

                    cidt.AddClaim(new Claim(ClaimTypes.NameIdentifier, eIdentifier, ClaimValueTypes.String, _issuer));
                    cidt.AddClaim(new Claim(eIdentifierAn, eIdentifier, ClaimValueTypes.String, _issuer));
                    cidt.AddClaim(new Claim(ClaimTypes.GivenName, GivenName, ClaimValueTypes.String, _issuer));
                    cidt.AddClaim(new Claim(ClaimTypes.Surname, Surname, ClaimValueTypes.String, _issuer));
                    cidt.AddClaim(new Claim(InheritedFamilyNameAN, InheritedFamilyName, ClaimValueTypes.String, _issuer));
                    cidt.AddClaim(new Claim(ClaimTypes.Email, Email, ClaimValueTypes.Email, _issuer));

                    ClaimsPrincipal cp = new ClaimsPrincipal(new ClaimsIdentity[] { cidt });
                    commandResult.Principal = cp;
                }
                commandResult.HttpStatusCode = System.Net.HttpStatusCode.Redirect;
                return commandResult;
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw;
            }
        }

        private const string htmlPostString = @"
<!DOCTYPE html>
<html>
<head>
    <title>Acceso a clave</title>
</head>
<body  onload=""document.forms[0].submit()""> 
    <div> 
       <form action=""{0}"" method=""post"">				
				<input type=""hidden"" name=""excludedIdpList"" value=""{1}""/>
				<input type=""hidden"" name=""forcedIdP"" value=""{2}""/>
				<input type=""hidden"" name=""SAMLRequest"" value=""{3}""/>		
    </form>
    </div>
</body>
</html>";
    }
}
