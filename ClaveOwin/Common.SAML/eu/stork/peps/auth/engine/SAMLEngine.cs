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
using System.Configuration;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;
using eu.stork.peps.auth.commons;
using NLog;

namespace eu.stork.peps.auth.engine
{
    /// <summary>
    ///
    /// </summary>
    public class SAMLEngine : ISAMLEngine
    {
        private static Logger _logger = LogManager.GetCurrentClassLogger();

        private const int MAX_STORED_IDS = 1000;
        private const int SKEW_CLOCK = 0;

        private static readonly XmlSerializerNamespaces _xmlNamespaces = new XmlSerializerNamespaces();
        private static SAMLEngine instance = null;

        private CitizenAttributes citizenAttributes;

        private string thisIssuer, thisDestination;

        private int validTimeframe;
        private int skewClock;

        private bool validateXsd;
        private XmlSchemaSet schemaSet;

        private List<string> receivedIds;
        private int receivedIdsIndex = 0;
        private ReaderWriterLock rwl = new ReaderWriterLock();

        // certificate with private and public keys to sign SAML requests/responses
        private X509Certificate2 certificate;

        static SAMLEngine()
        {
        }

        private SAMLEngine()
        {
            try
            {
                _xmlNamespaces.Add(SAMLConstants.NS_PROTOCOL_PREFIX, SAMLConstants.NS_PROTOCOL);
                _xmlNamespaces.Add(SAMLConstants.NS_ASSERT_PREFIX, SAMLConstants.NS_ASSERT);
                _xmlNamespaces.Add(ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_QAALEVEL_PREFIX),
                                    ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_QAALEVEL));
                _xmlNamespaces.Add(ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_REQ_ATTRS_PREFIX),
                                    ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_REQ_ATTRS));

                thisIssuer = ConfigurationSettingsHelper.GetCriticalConfigSetting("SPIssuer");
                validateXsd = ConfigurationSettingsHelper.GetCriticalConfigBoolSetting("SamlValidateXsdXml");

                thisDestination = ConfigurationManager.AppSettings["SamlDestinationAlias"];
                if (string.IsNullOrEmpty(thisDestination))
                    thisDestination = null;
                else
                    thisDestination = thisIssuer + thisDestination;
                validTimeframe = ConfigurationSettingsHelper.GetCriticalConfigIntSetting("SamlValidTimeframe");
                int? skewClockTmp = ConfigurationSettingsHelper.GetConfigIntSetting("SamlSkewClock");
                skewClock = skewClockTmp == null ? SKEW_CLOCK : (int)skewClockTmp;

                int capacity = ConfigurationSettingsHelper.GetConfigIntSetting("SamlNumberStoredIds") ?? MAX_STORED_IDS;
                receivedIds = new List<string>(capacity);

                string tumbprint = ConfigurationSettingsHelper.GetCriticalConfigSetting("SamlCertificate");
                certificate = CertificateUtils.GetCertificateFromPersonalStore(tumbprint);
                if (certificate == null || !certificate.HasPrivateKey)
                {
                    _logger.Trace("Certificate '" + tumbprint + "' not found at " +
                        "LocalMachine/My keystore or access to private key was denied. Certificate: " + certificate);
                    throw new SAMLException("Certificate '" + tumbprint + "' not found at " +
                        "LocalMachine/My keystore or access to private key was denied. Certificate: " + certificate);
                }

                citizenAttributes = CitizenAttributes.Instance;
            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// Instancia singleton
        /// </summary>
        public static SAMLEngine Instance
        {
            get
            {
                if (instance == null) instance = new SAMLEngine();
                return instance;
            }
        }

        /// <summary>
        /// Initializes this SAMLEngine object with the path to the project directory.
        /// This path is used for accessing the SAML xsd files.
        /// </summary>
        /// <param name="path"></param>
        public void Init(string path)
        {
            if (validateXsd)
            {
                path.Replace('\\', '/');
                if (!path.EndsWith("/"))
                    path = path + "/";
                schemaSet = new XmlSchemaSet();
                schemaSet.Add(SAMLConstants.NS_ASSERT, path + "XSD/saml-schema-assertion-2.0.xsd");
                schemaSet.Add(SAMLConstants.NS_PROTOCOL, path + "XSD/saml-schema-protocol-2.0.xsd");
                schemaSet.Add("http://www.w3.org/2000/09/xmldsig#", path + "XSD/xmldsig-core-schema.xsd");
                schemaSet.Add("http://www.w3.org/2001/04/xmlenc#", path + "XSD/xenc-schema.xsd");
                schemaSet.Compile();
            }
        }

        /// <summary>
        /// Initializes this SAMLEngine with resource XSD
        /// jcaubin
        /// </summary>
        /// <param name="path"></param>
        public void Init()
        {
            _logger.Trace("Start;");
            if (validateXsd)
            {
                schemaSet = new XmlSchemaSet();
                // load the XSD (schema) from the assembly's embedded resources and add it to schema set
                _logger.Trace("Ejecutar Assembly.GetExecutingAssembly()");
                Assembly assembly = Assembly.GetExecutingAssembly();
                using (var streamReader = new StreamReader(assembly.GetManifestResourceStream("eu.stork.peps.auth.engine.XSD.saml-schema-assertion-2.0.xsd")))
                {
                    schemaSet.Add(SAMLConstants.NS_ASSERT, XmlReader.Create(streamReader));
                }
                using (var streamReader = new StreamReader(assembly.GetManifestResourceStream("eu.stork.peps.auth.engine.XSD.saml-schema-protocol-2.0.xsd")))
                {
                    schemaSet.Add(SAMLConstants.NS_PROTOCOL, XmlReader.Create(streamReader));
                }
                using (var streamReader = new StreamReader(assembly.GetManifestResourceStream("eu.stork.peps.auth.engine.XSD.xmldsig-core-schema.xsd")))
                {
                    schemaSet.Add("http://www.w3.org/2000/09/xmldsig#", XmlReader.Create(streamReader));
                }
                using (var streamReader = new StreamReader(assembly.GetManifestResourceStream("eu.stork.peps.auth.engine.XSD.xenc-schema.xsd")))
                {
                    schemaSet.Add("http://www.w3.org/2001/04/xmlenc#", XmlReader.Create(streamReader));
                }
                _logger.Trace("Ejecutar schemaSet.Compile()");
                schemaSet.Compile();
            }
        }

        private void AddId(string id)
        {
            rwl.AcquireWriterLock(-1);
            try
            {
                receivedIds.Insert(receivedIdsIndex++, id);
                if (receivedIdsIndex == receivedIds.Capacity)
                    receivedIdsIndex = 0;
            }
            finally
            {
                rwl.ReleaseWriterLock();
            }
        }

        private bool IsRepeatedId(string id)
        {
            rwl.AcquireReaderLock(-1);
            try
            {
                return receivedIds.Contains(id);
            }
            finally
            {
                rwl.ReleaseReaderLock();
            }
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="doc"></param>
        /// <returns>a saml context to be used when generating the response</returns>
        private SAMLContext ExtractRequestValues(XmlDocument doc)
        {
            SAMLContext context = new SAMLContext(SAMLConstants.ErrorCodes.VALID);
            XmlReader reader = new XmlTextReader(new StringReader(doc.OuterXml));
            AuthnRequestType request = Deserialize<AuthnRequestType>(reader);
            context.AssertionConsumer = request.AssertionConsumerServiceURL;

            if (IsRepeatedId(request.ID))
            {
                context.ErrorCode = SAMLConstants.ErrorCodes.REPEATED_ID;
                return context;
            }
            AddId(request.ID);
            if (thisDestination != null && request.Destination != thisDestination)
            {
                context.ErrorCode = SAMLConstants.ErrorCodes.INVALID_DESTINATION;
                return context;
            }
            if (Math.Abs(request.IssueInstant.Subtract(DateTime.UtcNow).TotalMinutes) > validTimeframe)
            {
                context.ErrorCode = SAMLConstants.ErrorCodes.EXPIRED;
                return context;
            }

            context.Issuer = request.Issuer.Value;
            context.RequestID = request.ID;

            XmlElement[] xmlElement = request.Extensions.Any;
            XmlElement reqAttributes = null;
            foreach (XmlElement element in xmlElement)
                if (element.LocalName == "RequestedAttributes" &&
                    element.NamespaceURI == ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_REQ_ATTRS))
                {
                    reqAttributes = element;
                    break;
                }
            if (reqAttributes == null)
            {
                context.ErrorCode = SAMLConstants.ErrorCodes.XML_VALIDATION_FAILED;
                return context;
            }

            try
            {
                foreach (XmlElement element in reqAttributes.GetElementsByTagName("RequestedAttribute", ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_REQ_ATTR)))
                {
                    XmlAttributeCollection attrCollection = element.Attributes;
                    string name = attrCollection["Name"].Value;
                    // string nameFormat = attrColection["NameFormat"].Value;
                    string isRequired = attrCollection["isRequired"].Value;
                    context.AddAttribute(name, bool.Parse(isRequired));
                }
            }
            catch (Exception)
            {
                //something wrong happend with the attribute processing.
                //Problably the isRequiredAttribut is not present. Log the event and return an InvalidAttribute response
                context.ErrorCode = SAMLConstants.ErrorCodes.INVALID_ATTRIBUTES;
                return context;
            }

            if (context.GetAttributeNames().Count == 0)
                context.ErrorCode = SAMLConstants.ErrorCodes.INVALID_ATTRIBUTES;
            return context;
        }

        private SAMLResponse ExtractResponseValues(XmlDocument doc)
        {
            _logger.Trace("Start;");

            SAMLResponse context = new SAMLResponse(SAMLConstants.ErrorCodes.VALID);

            XmlReader reader = new XmlTextReader(new StringReader(doc.OuterXml));
            ResponseType response = Deserialize<ResponseType>(reader);

            context.InResponseTo = response.InResponseTo;
            context.Idp = response.Issuer.Value;
            int statusCode = SAMLConstants.StatusCode.GetStatusCodeFromDesc(response.Status.StatusCode.Value);
            if (statusCode < 0 && response.Status.StatusCode.StatusCode != null)
            {
                context.StatusCode = SAMLConstants.StatusCode.GetStatusCodeFromDesc(response.Status.StatusCode.StatusCode.Value);
            }
            else
            {
                context.StatusCode = statusCode;
            }

            if (Math.Abs(response.IssueInstant.Subtract(DateTime.UtcNow).TotalMinutes) > validTimeframe)
            {
                context.ErrorCode = SAMLConstants.ErrorCodes.EXPIRED;
                return context;
            }
            if (statusCode != SAMLConstants.StatusCode.SUCCESS)
            {
                int subStatusCode = SAMLConstants.StatusCode.GetStatusCodeFromDesc(response.Status.StatusCode.StatusCode.Value);
                if (subStatusCode != -1)
                {
                    context.SubStatusCode = subStatusCode;
                    context.StatusMessage = response.Status.StatusMessage;
                }
                return context;
            }

            int i;
            for (i = 0; i < response.Items.Length; i++)
                if (response.Items[i].GetType() == typeof(AssertionType))
                    break;
            AssertionType assertion = (AssertionType)response.Items[i];
            DateTime now = DateTime.UtcNow;
            TimeSpan tSpan = new TimeSpan(0, 0, skewClock);
            if (now < assertion.Conditions.NotBefore.Subtract(tSpan) || now >= assertion.Conditions.NotOnOrAfter.Add(tSpan))
            {
                context.ErrorCode = SAMLConstants.ErrorCodes.EXPIRED_ASSERTION;
                return context;
            }

            for (i = 0; i < assertion.Items.Length; i++)
                if (assertion.Items[i].GetType() == typeof(AttributeStatementType))
                    break;
            AttributeStatementType attrStatement = (AttributeStatementType)assertion.Items[i];

            foreach (object o in attrStatement.Items)
            {
                AttributeType attr = (AttributeType)o;

                if (!citizenAttributes.Exists(attr.Name))
                {
                    context.ErrorCode = SAMLConstants.ErrorCodes.INVALID_ATTRIBUTES;
                    return context;
                }
                int attrStatus = SAMLConstants.AttributeStatus.AVAILABLE;
                if (attr.AnyAttr != null)
                    for (i = 0; i < attr.AnyAttr.Length; i++)
                        if (attr.AnyAttr[i].LocalName == SAMLConstants.ATTRIBUTE_STATUS_STR)
                        {
                            attrStatus = SAMLConstants.AttributeStatus.GetAttrStatusFromDesc(attr.AnyAttr[i].Value);
                            break;
                        }
                string attrValue = null;
                if (attr.AttributeValue != null && attr.AttributeValue.Length > 0)
                {
                    if (attr.AttributeValue[0] is System.Xml.XmlNode[])
                    {
                        System.Xml.XmlNode[] nodeValues = ((System.Xml.XmlNode[])attr.AttributeValue[0]);
                        int size = nodeValues.Length;
                        Dictionary<string, string> values = new Dictionary<string, string>(size);
                        for (int j = 0; j < size; j++)
                        {
                            if (nodeValues[j].NodeType.Equals(System.Xml.XmlNodeType.Text))
                            {
                                values.Add((string)nodeValues[j].LocalName, (string)nodeValues[j].InnerText);
                            }
                        }
                        context.AddAttribute(attr.Name, values, attrStatus);
                    }
                    else
                    {
                        attrValue = (string)attr.AttributeValue[0];
                        context.AddAttribute(attr.Name, attrValue, attrStatus);
                    }
                }
                else
                {
                    context.AddAttribute(attr.Name, attrValue, attrStatus);
                }
            }
            if (context.GetAttributeNames().Count == 0)
                context.ErrorCode = SAMLConstants.ErrorCodes.INVALID_ATTRIBUTES;
            _logger.Trace("SAMLResponse {0}, {1}, {2}", context.StatusCode, context.StatusMessage, context.ErrorCode);
            _logger.Trace("SAMLResponse {0}, {1}", context.GetAttributeNames().Count, context.StatusMessage);
            return context;
        }

        private SAMLLogoutResponse ExtractLogoutResponseValues(XmlDocument doc)
        {
            SAMLLogoutResponse context = new SAMLLogoutResponse(SAMLConstants.ErrorCodes.VALID);

            XmlReader reader = new XmlTextReader(new StringReader(doc.OuterXml));
            LogoutResponseType response = Deserialize<LogoutResponseType>(reader);

            context.InResponseTo = response.InResponseTo;
            int statusCode = SAMLConstants.StatusCode.GetStatusCodeFromDesc(
                response.Status.StatusCode.Value);
            if (statusCode < 0 && response.Status.StatusCode.StatusCode != null)
            {
                context.StatusCode = SAMLConstants.StatusCode.GetStatusCodeFromDesc(
                response.Status.StatusCode.StatusCode.Value);
            }
            else
            {
                context.StatusCode = statusCode;
            }

            if (Math.Abs(response.IssueInstant.Subtract(DateTime.UtcNow).TotalMinutes) > validTimeframe)
            {
                context.ErrorCode = SAMLConstants.ErrorCodes.EXPIRED;
                return context;
            }
            if (statusCode != SAMLConstants.StatusCode.SUCCESS)
            {
                int subStatusCode = SAMLConstants.StatusCode.GetStatusCodeFromDesc(
                    response.Status.StatusCode.StatusCode.Value);
                if (subStatusCode != -1)
                {
                    context.SubStatusCode = subStatusCode;
                    context.StatusMessage = response.Status.StatusMessage;
                }
                return context;
            }

            return context;
        }

        /// <summary>
        /// Serializes the specified item to a stream.
        /// </summary>
        /// <typeparam name="T">The items type</typeparam>
        /// <param name="item">The item to serialize.</param>
        /// <param name="stream">The stream to serialize to.</param>
        public static void Serialize<T>(T item, Stream stream)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(T));
            serializer.Serialize(stream, item, _xmlNamespaces);
            stream.Flush();
        }

        /// <summary>
        /// Reads and deserializes an item from the reader
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="reader">The reader.</param>
        /// <returns></returns>
        public static T Deserialize<T>(XmlReader reader)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(T));
            T item = (T)serializer.Deserialize(reader);

            return item;
        }

        private XmlDocument GenerateRequestMetadata(SAMLRequest context)
        {
            DateTime now = DateTime.UtcNow;
            AuthnRequestType request = new AuthnRequestType();
            request.ID = context.Id;
            request.Version = SAMLConstants.SAML_VERSION;
            request.IssueInstant = now;
            request.Destination = context.Destination;
            request.Consent = SAMLConstants.CONSENT;
            request.ForceAuthn = true;
            request.IsPassive = false;
            request.ProtocolBinding = SAMLConstants.PROTOCOL_BINDING;
            request.AssertionConsumerServiceURL = context.AssertionConsumerServiceURL;
            request.ProviderName = context.ProviderName;
            request.Issuer = new NameIDType();
            request.Issuer.Value = context.Issuer;
            request.Issuer.Format = context.IssuerFormat;

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            XmlElement requestedAttrs = doc.CreateElement(ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_REQ_ATTRS_PREFIX),
                "RequestedAttributes", ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_REQ_ATTRS));
            foreach (AttributeElement attr in context.Attributes)
            {
                XmlElement requestedAttr = doc.CreateElement(ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_REQ_ATTR_PREFIX),
                    "RequestedAttribute", ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_REQ_ATTR));
                requestedAttr.SetAttribute("Name", attr.AttrName);
                requestedAttr.SetAttribute("NameFormat", SAMLConstants.ATTRIBUTE_NAME_FORMAT);
                requestedAttr.SetAttribute("isRequired", attr.IsRequired.ToString().ToLower());
                if (attr.AttrName.Equals(CommonConstants.FORCE_AUTH))
                {
                    XmlElement attrValue = doc.CreateElement(ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_REQ_ATTR_PREFIX),
                        "AttributeValue", ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_REQ_ATTR));
                    attrValue.InnerText = attr.AttrValue.ToString().ToLower();
                    requestedAttr.AppendChild(attrValue);
                }
                requestedAttrs.AppendChild(requestedAttr);
            }

            // stork extensions
            XmlElement qualityAuthnAssLevel = doc.CreateElement(ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_QAALEVEL_PREFIX),
                "QualityAuthenticationAssuranceLevel", ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_QAALEVEL));
            qualityAuthnAssLevel.InnerText = context.QAALevel;
            XmlElement spSectorEl = doc.CreateElement(SAMLConstants.NS_STORK_ASSER_PREFIX,
                "spSector", SAMLConstants.NS_STORK_ASSER);
            spSectorEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigIntSetting(CommonConstants.SAMLSECTOR).ToString();
            XmlElement spInstitutionEl = doc.CreateElement(SAMLConstants.NS_STORK_ASSER_PREFIX,
                "spInstitution", SAMLConstants.NS_STORK_ASSER);
            spInstitutionEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigSetting(CommonConstants.SAMLINSTITUTION);
            XmlElement spApplicationEl = doc.CreateElement(SAMLConstants.NS_STORK_ASSER_PREFIX,
                "spApplication", SAMLConstants.NS_STORK_ASSER);
            spApplicationEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigSetting(CommonConstants.SAMLAPPLICATION);
            XmlElement spCountryEl = doc.CreateElement(SAMLConstants.NS_STORK_ASSER_PREFIX,
                "spCountry", SAMLConstants.NS_STORK_ASSER);
            spCountryEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigSetting(CommonConstants.SAMLCOUNTRY);
            XmlElement eIDSectorShareEl = doc.CreateElement(SAMLConstants.NS_STORK_PROT_PREFIX,
                "eIDSectorShare", SAMLConstants.NS_STORK_PROT);
            eIDSectorShareEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigBoolSetting("SamlEIDSectorShare").ToString().ToLower();
            XmlElement eIDCrossSectorShareEl = doc.CreateElement(SAMLConstants.NS_STORK_PROT_PREFIX,
                "eIDCrossSectorShare", SAMLConstants.NS_STORK_PROT);
            eIDCrossSectorShareEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigBoolSetting("SamlEIDCrossSectorShare").ToString().ToLower();
            XmlElement eIDCrossBorderShareEl = doc.CreateElement(SAMLConstants.NS_STORK_PROT_PREFIX,
                "eIDCrossBorderShare", SAMLConstants.NS_STORK_PROT);
            eIDCrossBorderShareEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigBoolSetting("SamlEIDCrossBorderShare").ToString().ToLower();

            request.Extensions = new ExtensionsType();
            request.Extensions.Any = new XmlElement[] { qualityAuthnAssLevel, spSectorEl,
                spInstitutionEl, spApplicationEl, spCountryEl, eIDSectorShareEl,
                eIDCrossSectorShareEl, eIDCrossBorderShareEl, requestedAttrs};

            MemoryStream stream = new MemoryStream();
            Serialize(request, stream);

            StreamReader reader = new StreamReader(stream);
            stream.Seek(0, SeekOrigin.Begin);
            string xml = reader.ReadToEnd();
            XmlTextReader xmlReader = new XmlTextReader(new StringReader(xml));
            return Deserialize<XmlDocument>(xmlReader);
        }

        private XmlDocument GenerateLogoutRequestMetadata(SAMLLogoutRequest context)
        {
            DateTime now = DateTime.UtcNow;
            LogoutRequestType request = new LogoutRequestType();
            request.ID = context.Id;
            request.Version = SAMLConstants.SAML_VERSION;
            request.IssueInstant = now;
            request.Destination = context.Destination;
            request.Consent = SAMLConstants.CONSENT;
            request.Issuer = new NameIDType();
            request.Issuer.Value = context.Issuer;
            request.NameID = new NameIDType();
            request.NameID.Value = ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.SP_ID);

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;

            // stork extensions
            XmlElement qualityAuthnAssLevel = doc.CreateElement(ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_QAALEVEL_PREFIX),
                "QualityAuthenticationAssuranceLevel", ConfigurationSettingsHelper.GetCriticalConfigSetting(CommonConstants.NS_QAALEVEL));
            qualityAuthnAssLevel.InnerText = context.QAALevel;
            XmlElement spSectorEl = doc.CreateElement(SAMLConstants.NS_STORK_ASSER_PREFIX,
                "spSector", SAMLConstants.NS_STORK_ASSER);
            spSectorEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigIntSetting(CommonConstants.SAMLSECTOR).ToString();
            XmlElement spInstitutionEl = doc.CreateElement(SAMLConstants.NS_STORK_ASSER_PREFIX,
                "spInstitution", SAMLConstants.NS_STORK_ASSER);
            spInstitutionEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigSetting(CommonConstants.SAMLINSTITUTION);
            XmlElement spApplicationEl = doc.CreateElement(SAMLConstants.NS_STORK_ASSER_PREFIX,
                "spApplication", SAMLConstants.NS_STORK_ASSER);
            spApplicationEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigSetting(CommonConstants.SAMLAPPLICATION);
            XmlElement spCountryEl = doc.CreateElement(SAMLConstants.NS_STORK_ASSER_PREFIX,
                "spCountry", SAMLConstants.NS_STORK_ASSER);
            spCountryEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigSetting(CommonConstants.SAMLCOUNTRY);
            XmlElement eIDSectorShareEl = doc.CreateElement(SAMLConstants.NS_STORK_PROT_PREFIX,
                "eIDSectorShare", SAMLConstants.NS_STORK_PROT);
            eIDSectorShareEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigBoolSetting("SamlEIDSectorShare").ToString().ToLower();
            XmlElement eIDCrossSectorShareEl = doc.CreateElement(SAMLConstants.NS_STORK_PROT_PREFIX,
                "eIDCrossSectorShare", SAMLConstants.NS_STORK_PROT);
            eIDCrossSectorShareEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigBoolSetting("SamlEIDCrossSectorShare").ToString().ToLower();
            XmlElement eIDCrossBorderShareEl = doc.CreateElement(SAMLConstants.NS_STORK_PROT_PREFIX,
                "eIDCrossBorderShare", SAMLConstants.NS_STORK_PROT);
            eIDCrossBorderShareEl.InnerText = ConfigurationSettingsHelper
                .GetCriticalConfigBoolSetting("SamlEIDCrossBorderShare").ToString().ToLower();

            request.Extensions = new ExtensionsType();
            request.Extensions.Any = new XmlElement[] { qualityAuthnAssLevel, spSectorEl,
                spInstitutionEl, spApplicationEl, spCountryEl, eIDSectorShareEl,
                eIDCrossSectorShareEl, eIDCrossBorderShareEl};

            MemoryStream stream = new MemoryStream();
            Serialize(request, stream);

            StreamReader reader = new StreamReader(stream);
            stream.Seek(0, SeekOrigin.Begin);
            string xml = reader.ReadToEnd();
            XmlTextReader xmlReader = new XmlTextReader(new StringReader(xml));
            return Deserialize<XmlDocument>(xmlReader);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private XmlDocument GenerateResponseMetadata(SAMLContext context, string id)
        {
            DateTime now = DateTime.UtcNow;
            MemoryStream stream = new MemoryStream();
            StreamReader reader;
            XmlTextReader xmlReader;

            ResponseType response = new ResponseType();
            response.ID = id;
            response.InResponseTo = context.RequestID;
            response.Version = SAMLConstants.SAML_VERSION;
            response.IssueInstant = now;

            response.Destination = context.AssertionConsumer;
            response.Consent = SAMLConstants.CONSENT;
            response.Issuer = new NameIDType();
            response.Issuer.Value = thisIssuer;
            response.Issuer.Format = SAMLConstants.ThisIssuerFormat;

            response.Status = new StatusType();
            response.Status.StatusCode = new StatusCodeType();
            response.Status.StatusCode.Value = SAMLConstants.StatusCode.statusCode[context.StatusCode];
            if (context.StatusCode != SAMLConstants.StatusCode.SUCCESS)
            {
                response.Status.StatusCode.StatusCode = new StatusCodeType();
                response.Status.StatusCode.StatusCode.Value =
                    SAMLConstants.StatusCode.statusCode[context.SubStatusCode];
                response.Status.StatusMessage = context.StatusMessage;
            }

            AssertionType assertion = new AssertionType();
            assertion.ID = "_" + Guid.NewGuid().ToString();
            assertion.Version = SAMLConstants.SAML_VERSION;
            assertion.IssueInstant = now;

            assertion.Issuer = new NameIDType();
            assertion.Issuer.Value = thisIssuer;
            assertion.Issuer.Format = SAMLConstants.ThisIssuerFormat;

            assertion.Subject = new SubjectType();
            NameIDType nameId = new NameIDType();
            nameId.Format = "urn:oasis:names:tc:SAML:1.1:nameid- format:unspecified";
            //nameId.NameQualifier = "http://C-PEPS.gov.xx";
            nameId.Value = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

            SubjectConfirmationType subjectConfirmation = new SubjectConfirmationType();
            subjectConfirmation.Method = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
            subjectConfirmation.SubjectConfirmationData = new SubjectConfirmationDataType();
            subjectConfirmation.SubjectConfirmationData.Address = context.SubjectAddress;
            subjectConfirmation.SubjectConfirmationData.InResponseTo = context.RequestID;
            //subjectConfirmation.SubjectConfirmationData.NotBeforeString = "2010-02-03T17:06:18.099Z";
            subjectConfirmation.SubjectConfirmationData.NotOnOrAfterString =
                String.Format("{0:yyyy-MM-ddTHH:mm:ssZ}", now.AddMinutes(validTimeframe));
            subjectConfirmation.SubjectConfirmationData.Recipient = context.Issuer;
            assertion.Subject.Items = new object[] { nameId, subjectConfirmation };

            assertion.Conditions = new ConditionsType();
            assertion.Conditions.NotBeforeString = String.Format("{0:yyyy-MM-ddTHH:mm:ssZ}", now);
            assertion.Conditions.NotOnOrAfterString =
                String.Format("{0:yyyy-MM-ddTHH:mm:ssZ}", now.AddMinutes(validTimeframe));

            AudienceRestrictionType audience = new AudienceRestrictionType();
            audience.Audience = new string[] { context.Issuer }; // FIXME
            assertion.Conditions.Items = new ConditionAbstractType[] { audience, new OneTimeUseType() };

            AuthnStatementType authnStatement = new AuthnStatementType();
            authnStatement.AuthnInstant = now;
            authnStatement.AuthnContext = new AuthnContextType();

            List<AttributeElement> attributes = context.GetAttributes();
            object[] attributesDescription = new AttributeType[attributes.Count];
            AttributeType attr;
            XmlAttribute statusAttr;
            int i = 0;
            foreach (AttributeElement element in attributes)
            {
                attr = new AttributeType();
                attr.Name = element.AttrName;
                attr.NameFormat = element.NameFormat;
                if (context.StatusCode == SAMLConstants.StatusCode.SUCCESS)
                {
                    if (element.AttrStatus == SAMLConstants.AttributeStatus.AVAILABLE &&
                        element.AttrValue != null)
                        attr.AttributeValue = new object[] { element.AttrValue };
                    if (element.AttrStatus >= 0)
                    {
                        statusAttr = new XmlDocument().
                            CreateAttribute(SAMLConstants.ATTRIBUTE_STATUS_STR, SAMLConstants.NS_STORK_ASSER);
                        statusAttr.Value = element.Status;
                        attr.AnyAttr = new XmlAttribute[] { statusAttr };
                    }
                }
                attributesDescription[i++] = attr;
            }

            AttributeStatementType attributeStatement = new AttributeStatementType();
            attributeStatement.Items = attributesDescription;
            assertion.Items = new StatementAbstractType[] { authnStatement, attributeStatement };
            response.Items = new object[] { assertion };

            stream = new MemoryStream();
            Serialize(response, stream);

            reader = new StreamReader(stream);
            stream.Seek(0, SeekOrigin.Begin);
            xmlReader = new XmlTextReader(new StringReader(reader.ReadToEnd()));
            return Deserialize<XmlDocument>(xmlReader);
        }

        private bool VerifyXmlXsd(XmlDocument xml)
        {
            if (schemaSet == null)
                throw new SAMLException("This instance of SAMLEngine needs to be initialized with the 'Init' method.");

            bool noErrors = true;
            xml.Schemas = schemaSet;

            ValidationEventHandler validator = delegate (object sender, ValidationEventArgs e)
            {
                noErrors = false;
            };
            xml.Validate(validator);
            return noErrors;
        }

        public bool VerifyXmlXsd(XmlDocument xml, out string errorDescription)
        {
            if (schemaSet == null)
                throw new SAMLException("This instance of SAMLEngine needs to be initialized with the 'Init' method.");

            bool noErrors = true;
            xml.Schemas = schemaSet;

            string str = null;
            ValidationEventHandler validator = delegate (object sender, ValidationEventArgs e)
            {
                str = e.Message;
                noErrors = false;
            };
            xml.Validate(validator);
            errorDescription = str;
            return noErrors;
        }

        private int Verify(XmlDocument xml, string issuer)
        {
            _logger.Trace("Start.");
            if (xml == null)
                return SAMLConstants.ErrorCodes.NULL_XML;

            // verify xml against xsds
            if (validateXsd && !VerifyXmlXsd(xml))
                return SAMLConstants.ErrorCodes.XML_VALIDATION_FAILED;

            X509Certificate2 certificate = CertificateUtils.RetrieveCertificate(xml);
            // verify issuer
            //if (issuer != null)
            //{
            //    if (!ServiceProviders.Instance.IsAllowed(issuer))
            //        return SAMLConstants.ErrorCodes.UNKNOWN_ISSUER;

            //    string certThumbprint = ServiceProviders.Instance.GetCertificateThumbprint(issuer);
            //    if (!CertificateUtils.VerifyThumbprint(certificate, certThumbprint))
            //        return SAMLConstants.ErrorCodes.UNKNOWN_ISSUER;
            //}

            // verify certificate
            if (!CertificateUtils.IsCertificateValid(certificate))
                return SAMLConstants.ErrorCodes.INVALID_CERTIFICATE;

            // verify signature
            if (!SignatureUtils.VerifySignature(xml.DocumentElement))
                return SAMLConstants.ErrorCodes.INVALID_SIGNATURE;

            return SAMLConstants.ErrorCodes.VALID;
        }

        public XmlDocument GenerateRequest(SAMLRequest request)
        {
            try
            {
                XmlDocument xmlRequest = GenerateRequestMetadata(request);
                xmlRequest.PreserveWhitespace = true;
                SignatureUtils.SignDocument(xmlRequest, request.Id, certificate,
                    xmlRequest.GetElementsByTagName("Issuer", SAMLConstants.NS_ASSERT).Item(0));

                return xmlRequest;
            }
            catch (Exception ex)
            {
                throw new SAMLException("EXCEPTION GenerateRequest", ex);
            }
        }

        public XmlDocument GenerateLogoutRequest(SAMLLogoutRequest request)
        {
            try
            {
                XmlDocument xmlRequest = GenerateLogoutRequestMetadata(request);
                xmlRequest.PreserveWhitespace = true;
                SignatureUtils.SignDocument(xmlRequest, request.Id, certificate,
                    xmlRequest.GetElementsByTagName("Issuer", SAMLConstants.NS_ASSERT).Item(0));

                return xmlRequest;
            }
            catch (Exception ex)
            {
                throw new SAMLException("EXCEPTION GenerateRequest", ex);
            }
        }

        /// <summary>
        /// Given a SAML request, this function validates it, and extracts the requested attributes.
        /// </summary>
        /// <param name="doc">the xml corresponding to the SAML request</param>
        /// <returns>the context of the SAML request</returns>
        public SAMLContext HandleRequest(XmlDocument xmlRequest)
        {
            try
            {
                int errorCode;
                SAMLContext context;
                string issuer = xmlRequest.GetElementsByTagName("Issuer", SAMLConstants.NS_ASSERT).Item(0).InnerText;
                if ((errorCode = Verify(xmlRequest, issuer)) < 0)
                {
                    string assertionConsumer = xmlRequest.GetElementsByTagName("AuthnRequest",
                        SAMLConstants.NS_PROTOCOL).Item(0).Attributes["AssertionConsumerServiceURL"].Value;
                    string requestId = xmlRequest.DocumentElement.Attributes["ID"].Value;
                    context = new SAMLContext(errorCode, requestId, assertionConsumer);
                }
                else
                    context = ExtractRequestValues(xmlRequest);

                return context;
            }
            catch (Exception ex)
            {
                throw new SAMLException("EXCEPTION HandleRequest", ex);
            }
        }

        /// <summary>
        /// Generates a SAML response with the given attributes.
        /// </summary>
        /// <param name="attrs"></param>
        /// <returns>the xml corresponding to the SAML response</returns>
        public XmlDocument GenerateResponse(SAMLContext context)
        {
            try
            {
                string id = "_" + Guid.NewGuid().ToString();
                XmlDocument xmlResponse = GenerateResponseMetadata(context, id);
                xmlResponse.PreserveWhitespace = true;
                SignatureUtils.SignDocument(xmlResponse, id, certificate,
                    xmlResponse.GetElementsByTagName("Issuer", SAMLConstants.NS_ASSERT).Item(0));

                return xmlResponse;
            }
            catch (Exception ex)
            {
                throw new SAMLException("EXCEPTION GenerateResponse", ex);
            }
        }

        public SAMLResponse HandleResponse(XmlDocument xmlResponse)
        {
            _logger.Trace("Start;");
            try
            {
                int errorCode;
                SAMLResponse response;
                if ((errorCode = Verify(xmlResponse, null)) < 0)
                {
                    response = new SAMLResponse(errorCode);
                    _logger.Warn("Verify failure: {0}", errorCode);
                }
                else
                    response = ExtractResponseValues(xmlResponse);

                return response;
            }
            catch (Exception ex)
            {
                throw new SAMLException("EXCEPTION HandleResponse", ex);
            }
        }

        public SAMLLogoutResponse HandleLogoutResponse(XmlDocument xmlResponse)
        {
            try
            {
                int errorCode;
                SAMLLogoutResponse response;
                if ((errorCode = Verify(xmlResponse, null)) < 0)
                    response = new SAMLLogoutResponse(errorCode);
                else
                    response = ExtractLogoutResponseValues(xmlResponse);

                return response;
            }
            catch (Exception ex)
            {
                throw new SAMLException("EXCEPTION HandleLogoutResponse", ex);
            }
        }
    }
}