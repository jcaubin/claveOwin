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
using System.Text;
using System.Xml.Serialization;
using System.Xml;

//
// author: AMA – Agência para a Modernização Administrativa IP, PORTUGAL (www.ama.pt)
//
namespace eu.stork.peps.auth.engine
{	

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("Extensions", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class ExtensionsType
	{
		private XmlElement[] anyField;

		/// <remarks/>
		[XmlAnyElementAttribute()]
		public XmlElement[] Any
		{
			get
			{
				return this.anyField;
			}
			set
			{
				this.anyField = value;
			}
		}
	}

	/// <remarks/>
	[XmlIncludeAttribute(typeof(NameIDMappingRequestType))]
	[XmlIncludeAttribute(typeof(LogoutRequestType))]
	[XmlIncludeAttribute(typeof(ManageNameIDRequestType))]
	[XmlIncludeAttribute(typeof(ArtifactResolveType))]
	[XmlIncludeAttribute(typeof(AuthnRequestType))]
	[XmlIncludeAttribute(typeof(SubjectQueryAbstractType))]
	[XmlIncludeAttribute(typeof(AuthzDecisionQueryType))]
	[XmlIncludeAttribute(typeof(AttributeQueryType))]
	[XmlIncludeAttribute(typeof(AuthnQueryType))]
	[XmlIncludeAttribute(typeof(AssertionIDRequestType))]	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	public abstract class RequestAbstractType
	{
		private NameIDType issuerField;

        private NameIDType nameIDField;

		private SignatureType signatureField;

		private ExtensionsType extensionsField;

		private string idField;

		private string versionField;

		private System.DateTime issueInstantField;

		private string destinationField;

		private string consentField;

		/// <remarks/>
		[XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public NameIDType Issuer
		{
			get
			{
				return this.issuerField;
			}
			set
			{
				this.issuerField = value;
			}
		}
        
        /// <remarks/>
        [XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public NameIDType NameID
        {
            get
            {
                return this.nameIDField;
            }
            set
            {
                this.nameIDField = value;
            }
        }
        
        /// <remarks/>
		[XmlElementAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
		public SignatureType Signature
		{
			get
			{
				return this.signatureField;
			}
			set
			{
				this.signatureField = value;
			}
		}

		/// <remarks/>
		public ExtensionsType Extensions
		{
			get
			{
				return this.extensionsField;
			}
			set
			{
				this.extensionsField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string ID
		{
			get
			{
				return this.idField;
			}
			set
			{
				this.idField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string Version
		{
			get
			{
				return this.versionField;
			}
			set
			{
				this.versionField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public System.DateTime IssueInstant
		{
			get
			{
				return this.issueInstantField;
			}
			set
			{
				this.issueInstantField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Destination
		{
			get
			{
				return this.destinationField;
			}
			set
			{
				this.destinationField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Consent
		{
			get
			{
				return this.consentField;
			}
			set
			{
				this.consentField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("Status", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class StatusType
	{
		private StatusCodeType statusCodeField;

		private string statusMessageField;

		private StatusDetailType statusDetailField;

		/// <remarks/>
		public StatusCodeType StatusCode
		{
			get
			{
				return this.statusCodeField;
			}
			set
			{
				this.statusCodeField = value;
			}
		}

		/// <remarks/>
		public string StatusMessage
		{
			get
			{
				return this.statusMessageField;
			}
			set
			{
				this.statusMessageField = value;
			}
		}

		/// <remarks/>
		public StatusDetailType StatusDetail
		{
			get
			{
				return this.statusDetailField;
			}
			set
			{
				this.statusDetailField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("StatusCode", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class StatusCodeType
	{
		private StatusCodeType statusCodeField;

		private string valueField;

		/// <remarks/>
		public StatusCodeType StatusCode
		{
			get
			{
				return this.statusCodeField;
			}
			set
			{
				this.statusCodeField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Value
		{
			get
			{
				return this.valueField;
			}
			set
			{
				this.valueField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("StatusDetail", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class StatusDetailType
	{
		private XmlElement[] anyField;

		/// <remarks/>
		[XmlAnyElementAttribute()]
		public XmlElement[] Any
		{
			get
			{
				return this.anyField;
			}
			set
			{
				this.anyField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("AssertionIDRequest", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class AssertionIDRequestType : RequestAbstractType
	{
		private string[] assertionIDRefField;

		/// <remarks/>
		[XmlElementAttribute("AssertionIDRef", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", DataType = "NCName")]
		public string[] AssertionIDRef
		{
			get
			{
				return this.assertionIDRefField;
			}
			set
			{
				this.assertionIDRefField = value;
			}
		}
	}

	/// <remarks/>
	[XmlIncludeAttribute(typeof(AuthzDecisionQueryType))]
	[XmlIncludeAttribute(typeof(AttributeQueryType))]
	[XmlIncludeAttribute(typeof(AuthnQueryType))]	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("SubjectQuery", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public abstract  class SubjectQueryAbstractType : RequestAbstractType
	{
		private SubjectType subjectField;

		/// <remarks/>
		[XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public SubjectType Subject
		{
			get
			{
				return this.subjectField;
			}
			set
			{
				this.subjectField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("AuthnQuery", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public  class AuthnQueryType : SubjectQueryAbstractType
	{
		private RequestedAuthnContextType requestedAuthnContextField;

		private string sessionIndexField;

		/// <remarks/>
		public RequestedAuthnContextType RequestedAuthnContext
		{
			get
			{
				return this.requestedAuthnContextField;
			}
			set
			{
				this.requestedAuthnContextField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string SessionIndex
		{
			get
			{
				return this.sessionIndexField;
			}
			set
			{
				this.sessionIndexField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("RequestedAuthnContext", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public  class RequestedAuthnContextType
	{
		private string[] itemsField;

		private ItemsChoiceType7[] itemsElementNameField;

		private AuthnContextComparisonType comparisonField;

		private bool comparisonFieldSpecified;

		/// <remarks/>
		[XmlElementAttribute("AuthnContextClassRef", typeof(string), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", DataType = "anyURI")]
		[XmlElementAttribute("AuthnContextDeclRef", typeof(string), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", DataType = "anyURI")]
		[XmlChoiceIdentifierAttribute("ItemsElementName")]
		public string[] Items
		{
			get
			{
				return this.itemsField;
			}
			set
			{
				this.itemsField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute("ItemsElementName")]
		[XmlIgnoreAttribute()]
		public ItemsChoiceType7[] ItemsElementName
		{
			get
			{
				return this.itemsElementNameField;
			}
			set
			{
				this.itemsElementNameField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public AuthnContextComparisonType Comparison
		{
			get
			{
				return this.comparisonField;
			}
			set
			{
				this.comparisonField = value;
			}
		}

		/// <remarks/>
		[XmlIgnoreAttribute()]
		public bool ComparisonSpecified
		{
			get
			{
				return this.comparisonFieldSpecified;
			}
			set
			{
				this.comparisonFieldSpecified = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IncludeInSchema = false)]
	public enum ItemsChoiceType7
	{
		/// <remarks/>
		[XmlEnumAttribute("urn:oasis:names:tc:SAML:2.0:assertion:AuthnContextClassRef")]
		AuthnContextClassRef,

		/// <remarks/>
		[XmlEnumAttribute("urn:oasis:names:tc:SAML:2.0:assertion:AuthnContextDeclRef")]
		AuthnContextDeclRef,
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	public enum AuthnContextComparisonType
	{

		/// <remarks/>
		exact,

		/// <remarks/>
		minimum,

		/// <remarks/>
		maximum,

		/// <remarks/>
		better,
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("AttributeQuery", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class AttributeQueryType : SubjectQueryAbstractType
	{
		private AttributeType[] attributeField;

		/// <remarks/>
		[XmlElementAttribute("Attribute", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public AttributeType[] Attribute
		{
			get
			{
				return this.attributeField;
			}
			set
			{
				this.attributeField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("AuthzDecisionQuery", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public  class AuthzDecisionQueryType : SubjectQueryAbstractType
	{
		private ActionType[] actionField;

		private EvidenceType evidenceField;

		private string resourceField;

		/// <remarks/>
		[XmlElementAttribute("Action", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public ActionType[] Action
		{
			get
			{
				return this.actionField;
			}
			set
			{
				this.actionField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public EvidenceType Evidence
		{
			get
			{
				return this.evidenceField;
			}
			set
			{
				this.evidenceField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Resource
		{
			get
			{
				return this.resourceField;
			}
			set
			{
				this.resourceField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("AuthnRequest", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public  class AuthnRequestType : RequestAbstractType
	{
		private SubjectType subjectField;

		private NameIDPolicyType nameIDPolicyField;

		private ConditionsType conditionsField;

		private RequestedAuthnContextType requestedAuthnContextField;

		private ScopingType scopingField;

		private bool forceAuthnField;

		private bool forceAuthnFieldSpecified;

		private bool isPassiveField;

		private bool isPassiveFieldSpecified;

		private string protocolBindingField;

		private ushort assertionConsumerServiceIndexField;

		private bool assertionConsumerServiceIndexFieldSpecified;

		private string assertionConsumerServiceURLField;

		private ushort attributeConsumingServiceIndexField;

		private bool attributeConsumingServiceIndexFieldSpecified;

		private string providerNameField;

		/// <remarks/>
		[XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public SubjectType Subject
		{
			get
			{
				return this.subjectField;
			}
			set
			{
				this.subjectField = value;
			}
		}

		/// <remarks/>
		public NameIDPolicyType NameIDPolicy
		{
			get
			{
				return this.nameIDPolicyField;
			}
			set
			{
				this.nameIDPolicyField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public ConditionsType Conditions
		{
			get
			{
				return this.conditionsField;
			}
			set
			{
				this.conditionsField = value;
			}
		}

		/// <remarks/>
		public RequestedAuthnContextType RequestedAuthnContext
		{
			get
			{
				return this.requestedAuthnContextField;
			}
			set
			{
				this.requestedAuthnContextField = value;
			}
		}

		/// <remarks/>
		public ScopingType Scoping
		{
			get
			{
				return this.scopingField;
			}
			set
			{
				this.scopingField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public bool ForceAuthn
		{
			get
			{
				return this.forceAuthnField;
			}
			set
			{
				this.forceAuthnField = value;
			}
		}

		/// <remarks/>
		[XmlIgnoreAttribute()]
		public bool ForceAuthnSpecified
		{
			get
			{
				return this.forceAuthnFieldSpecified;
			}
			set
			{
				this.forceAuthnFieldSpecified = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public bool IsPassive
		{
			get
			{
				return this.isPassiveField;
			}
			set
			{
				this.isPassiveField = value;
			}
		}

		/// <remarks/>
		[XmlIgnoreAttribute()]
		public bool IsPassiveSpecified
		{
			get
			{
				return this.isPassiveFieldSpecified;
			}
			set
			{
				this.isPassiveFieldSpecified = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string ProtocolBinding
		{
			get
			{
				return this.protocolBindingField;
			}
			set
			{
				this.protocolBindingField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public ushort AssertionConsumerServiceIndex
		{
			get
			{
				return this.assertionConsumerServiceIndexField;
			}
			set
			{
				this.assertionConsumerServiceIndexField = value;
			}
		}

		/// <remarks/>
		[XmlIgnoreAttribute()]
		public bool AssertionConsumerServiceIndexSpecified
		{
			get
			{
				return this.assertionConsumerServiceIndexFieldSpecified;
			}
			set
			{
				this.assertionConsumerServiceIndexFieldSpecified = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string AssertionConsumerServiceURL
		{
			get
			{
				return this.assertionConsumerServiceURLField;
			}
			set
			{
				this.assertionConsumerServiceURLField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public ushort AttributeConsumingServiceIndex
		{
			get
			{
				return this.attributeConsumingServiceIndexField;
			}
			set
			{
				this.attributeConsumingServiceIndexField = value;
			}
		}

		/// <remarks/>
		[XmlIgnoreAttribute()]
		public bool AttributeConsumingServiceIndexSpecified
		{
			get
			{
				return this.attributeConsumingServiceIndexFieldSpecified;
			}
			set
			{
				this.attributeConsumingServiceIndexFieldSpecified = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string ProviderName
		{
			get
			{
				return this.providerNameField;
			}
			set
			{
				this.providerNameField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("NameIDPolicy", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class NameIDPolicyType
	{
		private string formatField;

		private string sPNameQualifierField;

		private bool allowCreateField;

		private bool allowCreateFieldSpecified;

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Format
		{
			get
			{
				return this.formatField;
			}
			set
			{
				this.formatField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string SPNameQualifier
		{
			get
			{
				return this.sPNameQualifierField;
			}
			set
			{
				this.sPNameQualifierField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public bool AllowCreate
		{
			get
			{
				return this.allowCreateField;
			}
			set
			{
				this.allowCreateField = value;
			}
		}

		/// <remarks/>
		[XmlIgnoreAttribute()]
		public bool AllowCreateSpecified
		{
			get
			{
				return this.allowCreateFieldSpecified;
			}
			set
			{
				this.allowCreateFieldSpecified = value;
			}
		}
	}

	/// <remarks/>
	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("Scoping", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class ScopingType
	{

		private IDPListType iDPListField;

		private string[] requesterIDField;

		private string proxyCountField;

		/// <remarks/>
		public IDPListType IDPList
		{
			get
			{
				return this.iDPListField;
			}
			set
			{
				this.iDPListField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute("RequesterID", DataType = "anyURI")]
		public string[] RequesterID
		{
			get
			{
				return this.requesterIDField;
			}
			set
			{
				this.requesterIDField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "nonNegativeInteger")]
		public string ProxyCount
		{
			get
			{
				return this.proxyCountField;
			}
			set
			{
				this.proxyCountField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("IDPList", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class IDPListType
	{
		private IDPEntryType[] iDPEntryField;

		private string getCompleteField;

		/// <remarks/>
		[XmlElementAttribute("IDPEntry")]
		public IDPEntryType[] IDPEntry
		{
			get
			{
				return this.iDPEntryField;
			}
			set
			{
				this.iDPEntryField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(DataType = "anyURI")]
		public string GetComplete
		{
			get
			{
				return this.getCompleteField;
			}
			set
			{
				this.getCompleteField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("IDPEntry", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class IDPEntryType
	{
		private string providerIDField;

		private string nameField;

		private string locField;

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string ProviderID
		{
			get
			{
				return this.providerIDField;
			}
			set
			{
				this.providerIDField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string Name
		{
			get
			{
				return this.nameField;
			}
			set
			{
				this.nameField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Loc
		{
			get
			{
				return this.locField;
			}
			set
			{
				this.locField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("Response", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class ResponseType : StatusResponseType
	{
		private object[] itemsField;

		/// <remarks/>
		[XmlElementAttribute("Assertion", typeof(AssertionType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		[XmlElementAttribute("EncryptedAssertion", typeof(EncryptedElementType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public object[] Items
		{
			get
			{
				return this.itemsField;
			}
			set
			{
				this.itemsField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("ArtifactResolve", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public  class ArtifactResolveType : RequestAbstractType
	{
		private string artifactField;

		/// <remarks/>
		public string Artifact
		{
			get
			{
				return this.artifactField;
			}
			set
			{
				this.artifactField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("ArtifactResponse", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public  class ArtifactResponseType : StatusResponseType
	{
		private XmlElement anyField;

		/// <remarks/>
		[XmlAnyElementAttribute()]
		public XmlElement Any
		{
			get
			{
				return this.anyField;
			}
			set
			{
				this.anyField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("ManageNameIDRequest", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public  class ManageNameIDRequestType : RequestAbstractType
	{
		private object itemField;

		private object item1Field;

		/// <remarks/>
		[XmlElementAttribute("EncryptedID", typeof(EncryptedElementType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		[XmlElementAttribute("NameId", typeof(NameIDType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public object Item
		{
			get
			{
				return this.itemField;
			}
			set
			{
				this.itemField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute("NewEncryptedID", typeof(EncryptedElementType))]
		[XmlElementAttribute("NewID", typeof(string))]
		[XmlElementAttribute("Terminate", typeof(TerminateType))]
		public object Item1
		{
			get
			{
				return this.item1Field;
			}
			set
			{
				this.item1Field = value;
			}
		}
	}

	

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("Terminate", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class TerminateType
	{
	}

	/// <remarks/>
	[XmlIncludeAttribute(typeof(NameIDMappingResponseType))]
	[XmlIncludeAttribute(typeof(ArtifactResponseType))]
	[XmlIncludeAttribute(typeof(ResponseType))]	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("ManageNameIDResponse", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class StatusResponseType
	{
		private NameIDType issuerField;

		private SignatureType signatureField;

		private ExtensionsType extensionsField;

		private StatusType statusField;

		private string idField;

		private string inResponseToField;

		private string versionField;

		private System.DateTime issueInstantField;

		private string destinationField;

		private string consentField;

		/// <remarks/>
		[XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public NameIDType Issuer
		{
			get
			{
				return this.issuerField;
			}
			set
			{
				this.issuerField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
		public SignatureType Signature
		{
			get
			{
				return this.signatureField;
			}
			set
			{
				this.signatureField = value;
			}
		}

		/// <remarks/>
		public ExtensionsType Extensions
		{
			get
			{
				return this.extensionsField;
			}
			set
			{
				this.extensionsField = value;
			}
		}

		/// <remarks/>
		public StatusType Status
		{
			get
			{
				return this.statusField;
			}
			set
			{
				this.statusField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string ID
		{
			get
			{
				return this.idField;
			}
			set
			{
				this.idField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "NCName")]
		public string InResponseTo
		{
			get
			{
				return this.inResponseToField;
			}
			set
			{
				this.inResponseToField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string Version
		{
			get
			{
				return this.versionField;
			}
			set
			{
				this.versionField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public System.DateTime IssueInstant
		{
			get
			{
				return this.issueInstantField;
			}
			set
			{
				this.issueInstantField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Destination
		{
			get
			{
				return this.destinationField;
			}
			set
			{
				this.destinationField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Consent
		{
			get
			{
				return this.consentField;
			}
			set
			{
				this.consentField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("LogoutRequest", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class LogoutRequestType : RequestAbstractType
	{
		private object itemField;

		private string[] sessionIndexField;

		private string reasonField;

		private System.DateTime notOnOrAfterField;

		private bool notOnOrAfterFieldSpecified;

		/// <remarks/>
		[XmlElementAttribute("BaseID", typeof(BaseIDAbstractType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		[XmlElementAttribute("EncryptedID", typeof(EncryptedElementType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		[XmlElementAttribute("NameId", typeof(NameIDType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public object Item
		{
			get
			{
				return this.itemField;
			}
			set
			{
				this.itemField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute("SessionIndex")]
		public string[] SessionIndex
		{
			get
			{
				return this.sessionIndexField;
			}
			set
			{
				this.sessionIndexField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string Reason
		{
			get
			{
				return this.reasonField;
			}
			set
			{
				this.reasonField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public System.DateTime NotOnOrAfter
		{
			get
			{
				return this.notOnOrAfterField;
			}
			set
			{
				this.notOnOrAfterField = value;
			}
		}

		/// <remarks/>
		[XmlIgnoreAttribute()]
		public bool NotOnOrAfterSpecified
		{
			get
			{
				return this.notOnOrAfterFieldSpecified;
			}
			set
			{
				this.notOnOrAfterFieldSpecified = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("NameIDMappingRequest", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public  class NameIDMappingRequestType : RequestAbstractType
	{
		private object itemField;

		private NameIDPolicyType nameIDPolicyField;

		/// <remarks/>
		[XmlElementAttribute("BaseID", typeof(BaseIDAbstractType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		[XmlElementAttribute("EncryptedID", typeof(EncryptedElementType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		[XmlElementAttribute("NameId", typeof(NameIDType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public object Item
		{
			get
			{
				return this.itemField;
			}
			set
			{
				this.itemField = value;
			}
		}

		/// <remarks/>
		public NameIDPolicyType NameIDPolicy
		{
			get
			{
				return this.nameIDPolicyField;
			}
			set
			{
				this.nameIDPolicyField = value;
			}
		}
	}

	/// <remarks/>	
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("NameIDMappingResponse", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public  class NameIDMappingResponseType : StatusResponseType
	{
		private object itemField;

		/// <remarks/>
		[XmlElementAttribute("EncryptedID", typeof(EncryptedElementType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		[XmlElementAttribute("NameId", typeof(NameIDType), Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
		public object Item
		{
			get
			{
				return this.itemField;
			}
			set
			{
				this.itemField = value;
			}
		}
	}

	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
	[XmlRootAttribute("LogoutResponse", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
	public class LogoutResponseType : StatusResponseType
	{		
	}	

}
