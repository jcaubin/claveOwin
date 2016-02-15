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
using System.Xml;
using System.Xml.Serialization;
using System.Security.Cryptography.Xml;

//
// author: AMA – Agência para a Modernização Administrativa IP, PORTUGAL (www.ama.pt)
//
namespace eu.stork.peps.auth.engine
{
	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("BaseID", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public abstract class BaseIDAbstractType
	{
		private string nameQualifierField;

		private string sPNameQualifierField;

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string NameQualifier
		{
			get
			{
				return this.nameQualifierField;
			}
			set
			{
				this.nameQualifierField = value;
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("NameID", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class NameIDType
	{
		private string nameQualifierField;

		private string sPNameQualifierField;

		private string formatField;

		private string sPProvidedIDField;

		private string valueField;

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string NameQualifier
		{
			get
			{
				return this.nameQualifierField;
			}
			set
			{
				this.nameQualifierField = value;
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
		public string SPProvidedID
		{
			get
			{
				return this.sPProvidedIDField;
			}
			set
			{
				this.sPProvidedIDField = value;
			}
		}

		/// <remarks/>
		[XmlTextAttribute()]
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
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("EncryptedID", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class EncryptedElementType
	{
		private EncryptedDataType encryptedDataField;

		private EncryptedKeyType[] encryptedKeyField;

		/// <remarks/>
		[XmlElementAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
		public EncryptedDataType EncryptedData
		{
			get
			{
				return this.encryptedDataField;
			}
			set
			{
				this.encryptedDataField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute("EncryptedKey", Namespace = "http://www.w3.org/2001/04/xmlenc#")]
		public EncryptedKeyType[] EncryptedKey
		{
			get
			{
				return this.encryptedKeyField;
			}
			set
			{
				this.encryptedKeyField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
	[XmlRootAttribute("EncryptedData", Namespace = "http://www.w3.org/2001/04/xmlenc#", IsNullable = false)]
	public class EncryptedDataType : EncryptedType
	{
	}

	/// <remarks/>
	[XmlIncludeAttribute(typeof(EncryptedKeyType))]
	[XmlIncludeAttribute(typeof(EncryptedDataType))]
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
	public abstract class EncryptedType
	{
		private EncryptionMethodType encryptionMethodField;

		private KeyInfoType keyInfoField;

		private CipherDataType cipherDataField;

		private EncryptionPropertiesType encryptionPropertiesField;

		private string idField;

		private string typeField;

		private string mimeTypeField;

		private string encodingField;

		/// <remarks/>
		public EncryptionMethodType EncryptionMethod
		{
			get
			{
				return this.encryptionMethodField;
			}
			set
			{
				this.encryptionMethodField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
		public KeyInfoType KeyInfo
		{
			get
			{
				return this.keyInfoField;
			}
			set
			{
				this.keyInfoField = value;
			}
		}

		/// <remarks/>
		public CipherDataType CipherData
		{
			get
			{
				return this.cipherDataField;
			}
			set
			{
				this.cipherDataField = value;
			}
		}

		/// <remarks/>
		public EncryptionPropertiesType EncryptionProperties
		{
			get
			{
				return this.encryptionPropertiesField;
			}
			set
			{
				this.encryptionPropertiesField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Type
		{
			get
			{
				return this.typeField;
			}
			set
			{
				this.typeField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string MimeType
		{
			get
			{
				return this.mimeTypeField;
			}
			set
			{
				this.mimeTypeField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Encoding
		{
			get
			{
				return this.encodingField;
			}
			set
			{
				this.encodingField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
	public class EncryptionMethodType
	{
		private string keySizeField;

		private byte[] oAEPparamsField;

		private XmlNode[] anyField;

		private string algorithmField;

		/// <remarks/>
		[XmlElementAttribute(DataType = "integer")]
		public string KeySize
		{
			get
			{
				return this.keySizeField;
			}
			set
			{
				this.keySizeField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(DataType = "base64Binary")]
		public byte[] OAEPparams
		{
			get
			{
				return this.oAEPparamsField;
			}
			set
			{
				this.oAEPparamsField = value;
			}
		}

		/// <remarks/>
		[XmlTextAttribute()]
		[XmlAnyElementAttribute()]
		public XmlNode[] Any
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

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Algorithm
		{
			get
			{
				return this.algorithmField;
			}
			set
			{
				this.algorithmField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("KeyInfo", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class KeyInfoType
	{
		private object[] itemsField;

		private ItemsChoiceType2[] itemsElementNameField;

		private string[] textField;

		private string idField;

		/// <remarks/>
		[XmlAnyElementAttribute()]
		[XmlElementAttribute("KeyName", typeof(string))]
		[XmlElementAttribute("KeyValue", typeof(KeyValueType))]
		[XmlElementAttribute("MgmtData", typeof(string))]
		[XmlElementAttribute("PGPData", typeof(PGPDataType))]
		[XmlElementAttribute("RetrievalMethod", typeof(RetrievalMethodType))]
		[XmlElementAttribute("SPKIData", typeof(SPKIDataType))]
		[XmlElementAttribute("X509Data", typeof(X509DataType))]
		[XmlChoiceIdentifierAttribute("ItemsElementName")]
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

		/// <remarks/>
		[XmlElementAttribute("ItemsElementName")]
		[XmlIgnoreAttribute()]
		public ItemsChoiceType2[] ItemsElementName
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
		[XmlTextAttribute()]
		public string[] Text
		{
			get
			{
				return this.textField;
			}
			set
			{
				this.textField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("KeyValue", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class KeyValueType
	{
		private object itemField;

		private string[] textField;

		/// <remarks/>
		[XmlAnyElementAttribute()]
		[XmlElementAttribute("DSAKeyValue", typeof(DSAKeyValueType))]
		[XmlElementAttribute("RSAKeyValue", typeof(RSAKeyValueType))]
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
		[XmlTextAttribute()]
		public string[] Text
		{
			get
			{
				return this.textField;
			}
			set
			{
				this.textField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("DSAKeyValue", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class DSAKeyValueType
	{
		private byte[] pField;

		private byte[] qField;

		private byte[] gField;

		private byte[] yField;

		private byte[] jField;

		private byte[] seedField;

		private byte[] pgenCounterField;

		/// <remarks/>
		[XmlElementAttribute(DataType = "base64Binary")]
		public byte[] P
		{
			get
			{
				return this.pField;
			}
			set
			{
				this.pField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(DataType = "base64Binary")]
		public byte[] Q
		{
			get
			{
				return this.qField;
			}
			set
			{
				this.qField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(DataType = "base64Binary")]
		public byte[] G
		{
			get
			{
				return this.gField;
			}
			set
			{
				this.gField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(DataType = "base64Binary")]
		public byte[] Y
		{
			get
			{
				return this.yField;
			}
			set
			{
				this.yField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(DataType = "base64Binary")]
		public byte[] J
		{
			get
			{
				return this.jField;
			}
			set
			{
				this.jField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(DataType = "base64Binary")]
		public byte[] Seed
		{
			get
			{
				return this.seedField;
			}
			set
			{
				this.seedField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(DataType = "base64Binary")]
		public byte[] PgenCounter
		{
			get
			{
				return this.pgenCounterField;
			}
			set
			{
				this.pgenCounterField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("RSAKeyValue", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class RSAKeyValueType
	{
		private byte[] modulusField;

		private byte[] exponentField;

		/// <remarks/>
		[XmlElementAttribute(DataType = "base64Binary")]
		public byte[] Modulus
		{
			get
			{
				return this.modulusField;
			}
			set
			{
				this.modulusField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(DataType = "base64Binary")]
		public byte[] Exponent
		{
			get
			{
				return this.exponentField;
			}
			set
			{
				this.exponentField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("PGPData", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class PGPDataType
	{
		private object[] itemsField;

		private ItemsChoiceType1[] itemsElementNameField;

		/// <remarks/>
		[XmlAnyElementAttribute()]
		[XmlElementAttribute("PGPKeyID", typeof(byte[]), DataType = "base64Binary")]
		[XmlElementAttribute("PGPKeyPacket", typeof(byte[]), DataType = "base64Binary")]
		[XmlChoiceIdentifierAttribute("ItemsElementName")]
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

		/// <remarks/>
		[XmlElementAttribute("ItemsElementName")]
		[XmlIgnoreAttribute()]
		public ItemsChoiceType1[] ItemsElementName
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", IncludeInSchema = false)]
	public enum ItemsChoiceType1
	{
		/// <remarks/>
		[XmlEnumAttribute("##any:")]
		Item,

		/// <remarks/>
		PGPKeyID,

		/// <remarks/>
		PGPKeyPacket,
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("RetrievalMethod", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class RetrievalMethodType
	{
		private TransformType[] transformsField;

		private string uRIField;

		private string typeField;

		/// <remarks/>
		[XmlArrayItemAttribute("Transform", IsNullable = false)]
		public TransformType[] Transforms
		{
			get
			{
				return this.transformsField;
			}
			set
			{
				this.transformsField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string URI
		{
			get
			{
				return this.uRIField;
			}
			set
			{
				this.uRIField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Type
		{
			get
			{
				return this.typeField;
			}
			set
			{
				this.typeField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("Transform", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class TransformType
	{
		private object[] itemsField;

		private string[] textField;

		private string algorithmField;

		/// <remarks/>
		[XmlAnyElementAttribute()]
		[XmlElementAttribute("XPath", typeof(string))]
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

		/// <remarks/>
		[XmlTextAttribute()]
		public string[] Text
		{
			get
			{
				return this.textField;
			}
			set
			{
				this.textField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Algorithm
		{
			get
			{
				return this.algorithmField;
			}
			set
			{
				this.algorithmField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("SPKIData", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class SPKIDataType
	{
		private byte[][] sPKISexpField;

		private XmlElement anyField;

		/// <remarks/>
		[XmlElementAttribute("SPKISexp", DataType = "base64Binary")]
		public byte[][] SPKISexp
		{
			get
			{
				return this.sPKISexpField;
			}
			set
			{
				this.sPKISexpField = value;
			}
		}

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
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("X509Data", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class X509DataType
	{
		private object[] itemsField;

		private ItemsChoiceType[] itemsElementNameField;

		/// <remarks/>
		[XmlAnyElementAttribute()]
		[XmlElementAttribute("X509CRL", typeof(byte[]), DataType = "base64Binary")]
		[XmlElementAttribute("X509Certificate", typeof(byte[]), DataType = "base64Binary")]
		[XmlElementAttribute("X509IssuerSerial", typeof(X509IssuerSerialType))]
		[XmlElementAttribute("X509SKI", typeof(byte[]), DataType = "base64Binary")]
		[XmlElementAttribute("X509SubjectName", typeof(string))]
		[XmlChoiceIdentifierAttribute("ItemsElementName")]
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

		/// <remarks/>
		[XmlElementAttribute("ItemsElementName")]
		[XmlIgnoreAttribute()]
		public ItemsChoiceType[] ItemsElementName
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	public class X509IssuerSerialType
	{
		private string x509IssuerNameField;

		private string x509SerialNumberField;

		/// <remarks/>
		public string X509IssuerName
		{
			get
			{
				return this.x509IssuerNameField;
			}
			set
			{
				this.x509IssuerNameField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(DataType = "integer")]
		public string X509SerialNumber
		{
			get
			{
				return this.x509SerialNumberField;
			}
			set
			{
				this.x509SerialNumberField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", IncludeInSchema = false)]
	public enum ItemsChoiceType
	{
		/// <remarks/>
		[XmlEnumAttribute("##any:")]
		Item,

		/// <remarks/>
		X509CRL,

		/// <remarks/>
		X509Certificate,

		/// <remarks/>
		X509IssuerSerial,

		/// <remarks/>
		X509SKI,

		/// <remarks/>
		X509SubjectName,
	}

	/// <remarks/>

	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", IncludeInSchema = false)]
	public enum ItemsChoiceType2
	{
		/// <remarks/>
		[XmlEnumAttribute("##any:")]
		Item,

		/// <remarks/>
		KeyName,

		/// <remarks/>
		KeyValue,

		/// <remarks/>
		MgmtData,

		/// <remarks/>
		PGPData,

		/// <remarks/>
		RetrievalMethod,

		/// <remarks/>
		SPKIData,

		/// <remarks/>
		X509Data,
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
	[XmlRootAttribute("CipherData", Namespace = "http://www.w3.org/2001/04/xmlenc#", IsNullable = false)]
	public class CipherDataType
	{
		private object itemField;

		/// <remarks/>
		[XmlElementAttribute("CipherReference", typeof(CipherReferenceType))]
		[XmlElementAttribute("CipherValue", typeof(byte[]), DataType = "base64Binary")]
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

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
	[XmlRootAttribute("CipherReference", Namespace = "http://www.w3.org/2001/04/xmlenc#", IsNullable = false)]
	public class CipherReferenceType
	{
		private TransformType[] itemField;

		private string uRIField;

		/// <remarks/>
		[XmlArrayAttribute("Transforms")]
		[XmlArrayItemAttribute("Transform", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
		public TransformType[] Item
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
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string URI
		{
			get
			{
				return this.uRIField;
			}
			set
			{
				this.uRIField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
	[XmlRootAttribute("EncryptionProperties", Namespace = "http://www.w3.org/2001/04/xmlenc#", IsNullable = false)]
	public class EncryptionPropertiesType
	{
		private EncryptionPropertyType[] encryptionPropertyField;

		private string idField;

		/// <remarks/>
		[XmlElementAttribute("EncryptionProperty")]
		public EncryptionPropertyType[] EncryptionProperty
		{
			get
			{
				return this.encryptionPropertyField;
			}
			set
			{
				this.encryptionPropertyField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
	[XmlRootAttribute("EncryptionProperty", Namespace = "http://www.w3.org/2001/04/xmlenc#", IsNullable = false)]
	public class EncryptionPropertyType
	{
		private XmlElement[] itemsField;

		private string[] textField;

		private string targetField;

		private string idField;

		private XmlAttribute[] anyAttrField;

		/// <remarks/>
		[XmlAnyElementAttribute()]
		public XmlElement[] Items
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
		[XmlTextAttribute()]
		public string[] Text
		{
			get
			{
				return this.textField;
			}
			set
			{
				this.textField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Target
		{
			get
			{
				return this.targetField;
			}
			set
			{
				this.targetField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
		[XmlAnyAttributeAttribute()]
		public XmlAttribute[] AnyAttr
		{
			get
			{
				return this.anyAttrField;
			}
			set
			{
				this.anyAttrField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
	[XmlRootAttribute("EncryptedKey", Namespace = "http://www.w3.org/2001/04/xmlenc#", IsNullable = false)]
	public class EncryptedKeyType : EncryptedType
	{
		private ReferenceList referenceListField;

		private string carriedKeyNameField;

		private string recipientField;

		/// <remarks/>
		public ReferenceList ReferenceList
		{
			get
			{
				return this.referenceListField;
			}
			set
			{
				this.referenceListField = value;
			}
		}

		/// <remarks/>
		public string CarriedKeyName
		{
			get
			{
				return this.carriedKeyNameField;
			}
			set
			{
				this.carriedKeyNameField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string Recipient
		{
			get
			{
				return this.recipientField;
			}
			set
			{
				this.recipientField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(AnonymousType = true)]
	[XmlRootAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#", IsNullable = false)]
	public class ReferenceList
	{
		private ReferenceType[] itemsField;

		private ItemsChoiceType3[] itemsElementNameField;

		/// <remarks/>
		[XmlElementAttribute("DataReference", typeof(ReferenceType))]
		[XmlElementAttribute("KeyReference", typeof(ReferenceType))]
		[XmlChoiceIdentifierAttribute("ItemsElementName")]
		public ReferenceType[] Items
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
		public ItemsChoiceType3[] ItemsElementName
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
	public class ReferenceType
	{
		private XmlElement[] anyField;

		private string uRIField;

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

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string URI
		{
			get
			{
				return this.uRIField;
			}
			set
			{
				this.uRIField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#", IncludeInSchema = false)]
	public enum ItemsChoiceType3
	{
		/// <remarks/>
		DataReference,

		/// <remarks/>
		KeyReference,
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("Assertion", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class AssertionType
	{
		private NameIDType issuerField;

		private SignatureType signatureField;

		private SubjectType subjectField;

		private ConditionsType conditionsField;

		private AdviceType adviceField;

		private StatementAbstractType[] itemsField;

		private string versionField;

		private string idField;

		private System.DateTime issueInstantField;

		/// <remarks/>
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
		public AdviceType Advice
		{
			get
			{
				return this.adviceField;
			}
			set
			{
				this.adviceField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute("AttributeStatement", typeof(AttributeStatementType))]
		[XmlElementAttribute("AuthnStatement", typeof(AuthnStatementType))]
		[XmlElementAttribute("AuthzDecisionStatement", typeof(AuthzDecisionStatementType))]
		[XmlElementAttribute("Statement", typeof(StatementAbstractType))]
		public StatementAbstractType[] Items
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("Signature", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class SignatureType
	{
		private SignedInfoType signedInfoField;

		private SignatureValueType signatureValueField;

		private KeyInfoType keyInfoField;

		private ObjectType[] objectField;

		private string idField;

		/// <remarks/>
		public SignedInfoType SignedInfo
		{
			get
			{
				return this.signedInfoField;
			}
			set
			{
				this.signedInfoField = value;
			}
		}

		/// <remarks/>
		public SignatureValueType SignatureValue
		{
			get
			{
				return this.signatureValueField;
			}
			set
			{
				this.signatureValueField = value;
			}
		}

		/// <remarks/>
		public KeyInfoType KeyInfo
		{
			get
			{
				return this.keyInfoField;
			}
			set
			{
				this.keyInfoField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute("Object")]
		public ObjectType[] Object
		{
			get
			{
				return this.objectField;
			}
			set
			{
				this.objectField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("SignedInfo", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class SignedInfoType
	{
		private CanonicalizationMethodType canonicalizationMethodField;

		private SignatureMethodType signatureMethodField;

		private ReferenceType1[] referenceField;

		private string idField;

		/// <remarks/>
		public CanonicalizationMethodType CanonicalizationMethod
		{
			get
			{
				return this.canonicalizationMethodField;
			}
			set
			{
				this.canonicalizationMethodField = value;
			}
		}

		/// <remarks/>
		public SignatureMethodType SignatureMethod
		{
			get
			{
				return this.signatureMethodField;
			}
			set
			{
				this.signatureMethodField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute("Reference")]
		public ReferenceType1[] Reference
		{
			get
			{
				return this.referenceField;
			}
			set
			{
				this.referenceField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("CanonicalizationMethod", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class CanonicalizationMethodType
	{
		private XmlNode[] anyField;

		private string algorithmField;

		/// <remarks/>
		[XmlTextAttribute()]
		[XmlAnyElementAttribute()]
		public XmlNode[] Any
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

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Algorithm
		{
			get
			{
				return this.algorithmField;
			}
			set
			{
				this.algorithmField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("SignatureMethod", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class SignatureMethodType
	{
		private string hMACOutputLengthField;

		private XmlNode[] anyField;

		private string algorithmField;

		/// <remarks/>
		[XmlElementAttribute(DataType = "integer")]
		public string HMACOutputLength
		{
			get
			{
				return this.hMACOutputLengthField;
			}
			set
			{
				this.hMACOutputLengthField = value;
			}
		}

		/// <remarks/>
		[XmlTextAttribute()]
		[XmlAnyElementAttribute()]
		public XmlNode[] Any
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

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Algorithm
		{
			get
			{
				return this.algorithmField;
			}
			set
			{
				this.algorithmField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(TypeName = "ReferenceType", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("Reference", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class ReferenceType1
	{
		private TransformType[] transformsField;

		private DigestMethodType digestMethodField;

		private byte[] digestValueField;

		private string idField;

		private string uRIField;

		private string typeField;

		/// <remarks/>
		[XmlArrayItemAttribute("Transform", IsNullable = false)]
		public TransformType[] Transforms
		{
			get
			{
				return this.transformsField;
			}
			set
			{
				this.transformsField = value;
			}
		}

		/// <remarks/>
		public DigestMethodType DigestMethod
		{
			get
			{
				return this.digestMethodField;
			}
			set
			{
				this.digestMethodField = value;
			}
		}

		/// <remarks/>
		[XmlElementAttribute(DataType = "base64Binary")]
		public byte[] DigestValue
		{
			get
			{
				return this.digestValueField;
			}
			set
			{
				this.digestValueField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string URI
		{
			get
			{
				return this.uRIField;
			}
			set
			{
				this.uRIField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Type
		{
			get
			{
				return this.typeField;
			}
			set
			{
				this.typeField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("DigestMethod", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class DigestMethodType
	{
		private XmlNode[] anyField;

		private string algorithmField;

		/// <remarks/>
		[XmlTextAttribute()]
		[XmlAnyElementAttribute()]
		public XmlNode[] Any
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

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Algorithm
		{
			get
			{
				return this.algorithmField;
			}
			set
			{
				this.algorithmField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("SignatureValue", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class SignatureValueType
	{
		private string idField;

		private byte[] valueField;

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
		[XmlTextAttribute(DataType = "base64Binary")]
		public byte[] Value
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
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("Object", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class ObjectType
	{
		private XmlNode[] anyField;

		private string idField;

		private string mimeTypeField;

		private string encodingField;

		/// <remarks/>
		[XmlTextAttribute()]
		[XmlAnyElementAttribute()]
		public XmlNode[] Any
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

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
		public string MimeType
		{
			get
			{
				return this.mimeTypeField;
			}
			set
			{
				this.mimeTypeField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Encoding
		{
			get
			{
				return this.encodingField;
			}
			set
			{
				this.encodingField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("Subject", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class SubjectType
	{
		private object[] itemsField;

		/// <remarks/>
		[XmlElementAttribute("BaseID", typeof(BaseIDAbstractType))]
		[XmlElementAttribute("EncryptedID", typeof(EncryptedElementType))]
		[XmlElementAttribute("NameID", typeof(NameIDType))]
		[XmlElementAttribute("SubjectConfirmation", typeof(SubjectConfirmationType))]
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
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("SubjectConfirmation", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class SubjectConfirmationType
	{

		private object itemField;

		private SubjectConfirmationDataType subjectConfirmationDataField;

		private string methodField;

		/// <remarks/>
		[XmlElementAttribute("BaseID", typeof(BaseIDAbstractType))]
		[XmlElementAttribute("EncryptedID", typeof(EncryptedElementType))]
		[XmlElementAttribute("NameID", typeof(NameIDType))]
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
		public SubjectConfirmationDataType SubjectConfirmationData
		{
			get
			{
				return this.subjectConfirmationDataField;
			}
			set
			{
				this.subjectConfirmationDataField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Method
		{
			get
			{
				return this.methodField;
			}
			set
			{
				this.methodField = value;
			}
		}
	}

	/// <remarks/>
	[XmlIncludeAttribute(typeof(KeyInfoConfirmationDataType))]
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("SubjectConfirmationData", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class SubjectConfirmationDataType
	{
		private string[] textField;

        private DateTime notOnOrAfterField;

        //private DateTime notBeforeField;

        private string recipientField;

        private string inResponseToField;

        private string addressField;

        private XmlAttribute[] anyAttrField;

        private XmlElement[] anyElementField;

        [XmlAttributeAttribute("NotOnOrAfter")]
        public string NotOnOrAfterString
        {
            get { return XmlConvert.ToString(this.notOnOrAfterField, XmlDateTimeSerializationMode.Utc);}
            set { this.notOnOrAfterField = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);}
        }

        [XmlIgnore]
        public DateTime NotOnOrAfter 
        {
            get { return notOnOrAfterField;}
            set { notOnOrAfterField = value; }
        }
        /*
        [XmlAttributeAttribute("NotBefore")]
        public string NotBeforeString
        {
            get { return XmlConvert.ToString(this.notBeforeField, XmlDateTimeSerializationMode.Utc); }
            set { this.notBeforeField = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc); }
        }

        [XmlIgnore]
        public DateTime NotBefore
        {
            get { return notBeforeField; }
            set { notBeforeField = value; }
        }
        */
        [XmlAttributeAttribute]
        public string Recipient
        {
            get { return recipientField; }
            set { recipientField = value; }
        }

        [XmlAttributeAttribute]
        public string InResponseTo
        {
            get { return inResponseToField; }
            set { inResponseToField = value; }
        }

        [XmlAttributeAttribute]
        public string Address
        {
            get { return addressField; }
            set { addressField = value; }
        }

        [XmlAnyAttribute]
        public XmlAttribute[] AnyAttr
        {
            get { return anyAttrField; }
            set { anyAttrField = value; }
        }

        [XmlAnyElement]
        public XmlElement[] AnyElements
        {
            get { return anyElementField; }
            set { anyElementField = value; }
        }

		/// <remarks/>
		[XmlTextAttribute()]
		public string[] Text
		{
			get
			{
				return this.textField;
			}
			set
			{
				this.textField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	public class KeyInfoConfirmationDataType : SubjectConfirmationDataType
	{
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("Conditions", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class ConditionsType
	{
		private ConditionAbstractType[] itemsField;

		private System.DateTime notBeforeField;

		private bool notBeforeFieldSpecified;

		private System.DateTime notOnOrAfterField;

		private bool notOnOrAfterFieldSpecified;

		/// <remarks/>
		[XmlElementAttribute("AudienceRestriction", typeof(AudienceRestrictionType))]
		[XmlElementAttribute("Condition", typeof(ConditionAbstractType))]
		[XmlElementAttribute("OneTimeUse", typeof(OneTimeUseType))]
		[XmlElementAttribute("ProxyRestriction", typeof(ProxyRestrictionType))]
		public ConditionAbstractType[] Items
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
        [XmlAttributeAttribute("NotBefore")]
        public string NotBeforeString
        {
            get
            {
                return XmlConvert.ToString(this.notBeforeField, XmlDateTimeSerializationMode.Utc);
            }
            set
            {
                this.notBeforeField = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);
            }
        }

		/// <remarks/>
		[XmlIgnoreAttribute()]
		public System.DateTime NotBefore
		{
			get
			{
				return this.notBeforeField;
			}
			set
			{
				this.notBeforeField = value;
			}
		}

		/// <remarks/>
		[XmlIgnoreAttribute()]
		public bool NotBeforeSpecified
		{
			get
			{
				return this.notBeforeFieldSpecified;
			}
			set
			{
				this.notBeforeFieldSpecified = value;
			}
		}

        /// <remarks/>
        [XmlAttributeAttribute("NotOnOrAfter")]
        public string NotOnOrAfterString
        {
            get
            {
                return XmlConvert.ToString(this.notOnOrAfterField, XmlDateTimeSerializationMode.Utc);
            }
            set
            {
                this.notOnOrAfterField = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);
            }
        }

		/// <remarks/>
		[XmlIgnoreAttribute()]
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
	[XmlIncludeAttribute(typeof(ProxyRestrictionType))]
	[XmlIncludeAttribute(typeof(OneTimeUseType))]
	[XmlIncludeAttribute(typeof(AudienceRestrictionType))]
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("Condition", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public abstract class ConditionAbstractType
	{
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("AudienceRestriction", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class AudienceRestrictionType : ConditionAbstractType
	{

		private string[] audienceField;

		/// <remarks/>
		[XmlElementAttribute("Audience", DataType = "anyURI")]
		public string[] Audience
		{
			get
			{
				return this.audienceField;
			}
			set
			{
				this.audienceField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("OneTimeUse", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class OneTimeUseType : ConditionAbstractType
	{
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("ProxyRestriction", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class ProxyRestrictionType : ConditionAbstractType
	{

		private string[] audienceField;

		private string countField;

		/// <remarks/>
		[XmlElementAttribute("Audience", DataType = "anyURI")]
		public string[] Audience
		{
			get
			{
				return this.audienceField;
			}
			set
			{
				this.audienceField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "nonNegativeInteger")]
		public string Count
		{
			get
			{
				return this.countField;
			}
			set
			{
				this.countField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("Advice", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class AdviceType
	{
		private object[] itemsField;

		private ItemsChoiceType4[] itemsElementNameField;

		/// <remarks/>
		[XmlAnyElementAttribute()]
		[XmlElementAttribute("Assertion", typeof(AssertionType))]
		[XmlElementAttribute("AssertionIDRef", typeof(string), DataType = "NCName")]
		[XmlElementAttribute("AssertionURIRef", typeof(string), DataType = "anyURI")]
		[XmlElementAttribute("EncryptedAssertion", typeof(EncryptedElementType))]
		[XmlChoiceIdentifierAttribute("ItemsElementName")]
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

		/// <remarks/>
		[XmlElementAttribute("ItemsElementName")]
		[XmlIgnoreAttribute()]
		public ItemsChoiceType4[] ItemsElementName
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IncludeInSchema = false)]
	public enum ItemsChoiceType4
	{
		/// <remarks/>
		[XmlEnumAttribute("##any:")]
		Item,

		/// <remarks/>
		Assertion,

		/// <remarks/>
		AssertionIDRef,

		/// <remarks/>
		AssertionURIRef,

		/// <remarks/>
		EncryptedAssertion,
	}

	/// <remarks/>
	[XmlIncludeAttribute(typeof(AttributeStatementType))]
	[XmlIncludeAttribute(typeof(AuthzDecisionStatementType))]
	[XmlIncludeAttribute(typeof(AuthnStatementType))]
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("Statement", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public abstract class StatementAbstractType
	{
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("AuthnStatement", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class AuthnStatementType : StatementAbstractType
	{

		private SubjectLocalityType subjectLocalityField;

		private AuthnContextType authnContextField;

		private System.DateTime authnInstantField;

		private string sessionIndexField;

		private System.DateTime sessionNotOnOrAfterField;

		private bool sessionNotOnOrAfterFieldSpecified;

		/// <remarks/>
		public SubjectLocalityType SubjectLocality
		{
			get
			{
				return this.subjectLocalityField;
			}
			set
			{
				this.subjectLocalityField = value;
			}
		}

		/// <remarks/>
		public AuthnContextType AuthnContext
		{
			get
			{
				return this.authnContextField;
			}
			set
			{
				this.authnContextField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public System.DateTime AuthnInstant
		{
			get
			{
				return this.authnInstantField;
			}
			set
			{
				this.authnInstantField = value;
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

		/// <remarks/>
		[XmlAttributeAttribute()]
		public System.DateTime SessionNotOnOrAfter
		{
			get
			{
				return this.sessionNotOnOrAfterField;
			}
			set
			{
				this.sessionNotOnOrAfterField = value;
			}
		}

		/// <remarks/>
		[XmlIgnoreAttribute()]
		public bool SessionNotOnOrAfterSpecified
		{
			get
			{
				return this.sessionNotOnOrAfterFieldSpecified;
			}
			set
			{
				this.sessionNotOnOrAfterFieldSpecified = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("SubjectLocality", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class SubjectLocalityType
	{
		private string addressField;

		private string dNSNameField;

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string Address
		{
			get
			{
				return this.addressField;
			}
			set
			{
				this.addressField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string DNSName
		{
			get
			{
				return this.dNSNameField;
			}
			set
			{
				this.dNSNameField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("AuthnContext", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class AuthnContextType
	{
		private object[] itemsField;

		private ItemsChoiceType5[] itemsElementNameField;

		private string[] authenticatingAuthorityField;

		/// <remarks/>
		[XmlElementAttribute("AuthnContextClassRef", typeof(string), DataType = "anyURI")]
		[XmlElementAttribute("AuthnContextDecl", typeof(object))]
		[XmlElementAttribute("AuthnContextDeclRef", typeof(string), DataType = "anyURI")]
		[XmlChoiceIdentifierAttribute("ItemsElementName")]
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

		/// <remarks/>
		[XmlElementAttribute("ItemsElementName")]
		[XmlIgnoreAttribute()]
		public ItemsChoiceType5[] ItemsElementName
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
		[XmlElementAttribute("AuthenticatingAuthority", DataType = "anyURI")]
		public string[] AuthenticatingAuthority
		{
			get
			{
				return this.authenticatingAuthorityField;
			}
			set
			{
				this.authenticatingAuthorityField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IncludeInSchema = false)]
	public enum ItemsChoiceType5
	{

		/// <remarks/>
		AuthnContextClassRef,

		/// <remarks/>
		AuthnContextDecl,

		/// <remarks/>
		AuthnContextDeclRef,
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("SignatureProperty", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class SignaturePropertyType
	{

		private XmlElement[] itemsField;

		private string[] textField;

		private string targetField;

		private string idField;

		/// <remarks/>
		[XmlAnyElementAttribute()]
		public XmlElement[] Items
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
		[XmlTextAttribute()]
		public string[] Text
		{
			get
			{
				return this.textField;
			}
			set
			{
				this.textField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Target
		{
			get
			{
				return this.targetField;
			}
			set
			{
				this.targetField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("SignatureProperties", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class SignaturePropertiesType
	{

		private SignaturePropertyType[] signaturePropertyField;

		private string idField;

		/// <remarks/>
		[XmlElementAttribute("SignatureProperty")]
		public SignaturePropertyType[] SignatureProperty
		{
			get
			{
				return this.signaturePropertyField;
			}
			set
			{
				this.signaturePropertyField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("Manifest", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class ManifestType
	{

		private ReferenceType1[] referenceField;

		private string idField;

		/// <remarks/>
		[XmlElementAttribute("Reference")]
		public ReferenceType1[] Reference
		{
			get
			{
				return this.referenceField;
			}
			set
			{
				this.referenceField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "ID")]
		public string Id
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
	[XmlRootAttribute("AgreementMethod", Namespace = "http://www.w3.org/2001/04/xmlenc#", IsNullable = false)]
	public class AgreementMethodType
	{

		private byte[] kANonceField;

		private XmlNode[] anyField;

		private KeyInfoType originatorKeyInfoField;

		private KeyInfoType recipientKeyInfoField;

		private string algorithmField;

		/// <remarks/>
		[XmlElementAttribute("KA-Nonce", DataType = "base64Binary")]
		public byte[] KANonce
		{
			get
			{
				return this.kANonceField;
			}
			set
			{
				this.kANonceField = value;
			}
		}

		/// <remarks/>
		[XmlTextAttribute()]
		[XmlAnyElementAttribute()]
		public XmlNode[] Any
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

		/// <remarks/>
		public KeyInfoType OriginatorKeyInfo
		{
			get
			{
				return this.originatorKeyInfoField;
			}
			set
			{
				this.originatorKeyInfoField = value;
			}
		}

		/// <remarks/>
		public KeyInfoType RecipientKeyInfo
		{
			get
			{
				return this.recipientKeyInfoField;
			}
			set
			{
				this.recipientKeyInfoField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Algorithm
		{
			get
			{
				return this.algorithmField;
			}
			set
			{
				this.algorithmField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("AuthzDecisionStatement", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class AuthzDecisionStatementType : StatementAbstractType
	{

		private ActionType[] actionField;

		private EvidenceType evidenceField;

		private string resourceField;

		private DecisionType decisionField;

		/// <remarks/>
		[XmlElementAttribute("Action")]
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

		/// <remarks/>
		[XmlAttributeAttribute()]
		public DecisionType Decision
		{
			get
			{
				return this.decisionField;
			}
			set
			{
				this.decisionField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	public enum DecisionType
	{

		/// <remarks/>
		Permit,

		/// <remarks/>
		Deny,

		/// <remarks/>
		Indeterminate,
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("Action", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class ActionType
	{
		private string namespaceField;

		private string valueField;

		/// <remarks/>
		[XmlAttributeAttribute(DataType = "anyURI")]
		public string Namespace
		{
			get
			{
				return this.namespaceField;
			}
			set
			{
				this.namespaceField = value;
			}
		}

		/// <remarks/>
		[XmlTextAttribute()]
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
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("Evidence", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class EvidenceType
	{
		private object[] itemsField;

		private ItemsChoiceType6[] itemsElementNameField;

		/// <remarks/>
		[XmlElementAttribute("Assertion", typeof(AssertionType))]
		[XmlElementAttribute("AssertionIDRef", typeof(string), DataType = "NCName")]
		[XmlElementAttribute("AssertionURIRef", typeof(string), DataType = "anyURI")]
		[XmlElementAttribute("EncryptedAssertion", typeof(EncryptedElementType))]
		[XmlChoiceIdentifierAttribute("ItemsElementName")]
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

		/// <remarks/>
		[XmlElementAttribute("ItemsElementName")]
		[XmlIgnoreAttribute()]
		public ItemsChoiceType6[] ItemsElementName
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
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IncludeInSchema = false)]
	public enum ItemsChoiceType6
	{

		/// <remarks/>
		Assertion,

		/// <remarks/>
		AssertionIDRef,

		/// <remarks/>
		AssertionURIRef,

		/// <remarks/>
		EncryptedAssertion,
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("AttributeStatement", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class AttributeStatementType : StatementAbstractType
	{
		private object[] itemsField;

		/// <remarks/>
		[XmlElementAttribute("Attribute", typeof(AttributeType))]
		[XmlElementAttribute("EncryptedAttribute", typeof(EncryptedElementType))]
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
	[XmlTypeAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
	[XmlRootAttribute("Attribute", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = false)]
	public class AttributeType
	{
		private object[] attributeValueField;

		private string nameField;

		private string nameFormatField;

		private string friendlyNameField;

		private XmlAttribute[] anyAttrField;

		/// <remarks/>
		[XmlElementAttribute("AttributeValue", IsNullable = true)]
		public object[] AttributeValue
		{
			get
			{
				return this.attributeValueField;
			}
			set
			{
				this.attributeValueField = value;
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
		public string NameFormat
		{
			get
			{
				return this.nameFormatField;
			}
			set
			{
				this.nameFormatField = value;
			}
		}

		/// <remarks/>
		[XmlAttributeAttribute()]
		public string FriendlyName
		{
			get
			{
				return this.friendlyNameField;
			}
			set
			{
				this.friendlyNameField = value;
			}
		}

		/// <remarks/>
		[XmlAnyAttributeAttribute()]
		public XmlAttribute[] AnyAttr
		{
			get
			{
				return this.anyAttrField;
			}
			set
			{
				this.anyAttrField = value;
			}
		}
	}

	/// <remarks/>
	[XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
	[XmlRootAttribute("Transforms", Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
	public class TransformsType
	{
		private TransformType[] transformField;

		/// <remarks/>
		[XmlElementAttribute("Transform")]
		public TransformType[] Transform
		{
			get
			{
				return this.transformField;
			}
			set
			{
				this.transformField = value;
			}
		}
	}

}
