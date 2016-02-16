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

using eu.stork.peps.auth.commons.Exceptions;
using NLog;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

//
// author: AMA – Agência para a Modernização Administrativa IP, PORTUGAL (www.ama.pt)
//
namespace eu.stork.peps.auth.commons
{
    /// <summary>
    /// This class contains signature related methods
    /// </summary>
    public class SignatureUtils
    {
        private static Logger _logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// The XML namespace of XmlDSig
        /// </summary>
        public const string XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";

        /// <summary>
        /// Verifies if a signature within an xml document is valid
        /// </summary>
        /// <param name="doc">an xml document with a signature element</param>
        /// <returns>true if the signature is valid; false otherwise</returns>
        public static bool VerifySignature(XmlDocument doc)
        {
            try
            {
                if (!doc.PreserveWhitespace)
                    return false;
                return VerifySignature(doc.DocumentElement);
            }
            catch (Exception ex)
            {
                _logger.Error(ex);
                throw new SignatureUtilsException("Exception occurred on SignatureUtils.VerifySignature", ex);
            }
        }

        /// <summary>
        /// Verifies if a signature within an xml element is valid
        /// </summary>
        /// <param name="doc">an xml document with a signature element</param>
        /// <returns>true if the signature is valid; false otherwise</returns>
        public static bool VerifySignature(XmlElement element)
        {
            try
            {
                XmlNode signature = element.GetElementsByTagName("Signature", XMLDSIG)[0];

                SignedXml signedXml = new SignedXml(element);

                CryptoConfig.AddAlgorithm(typeof(RsaPkCs1Sha256SignatureDescription), @"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

                signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

                signedXml.LoadXml((XmlElement)signature);
                return signedXml.CheckSignature();
            }
            catch (Exception ex)
            {
                _logger.Error(ex);
                throw new SignatureUtilsException("Exception occurred on SignatureUtils.VerifySignature", ex);
            }
        }

        /// <summary>
        /// Given a certificate, this method verifies if the signature within an xml document is valid or not
        /// </summary>
        /// <param name="el">an xml document element</param>
        /// <param name="certPub">a certificate containing the public key to be used on the signature</param>
        /// <returns>true if the signature is valid; else otherwise</returns>
        //public static bool VerifySignature(XmlElement el, X509Certificate2 certPub)
        //{
        //    try
        //    {
        //        SignedXml signedXml = new SignedXml(el);

        //        XmlNodeList nodeList = el.GetElementsByTagName("Signature", XMLDSIG);
        //        if (nodeList.Count == 0) // Document does not contain a signature to verify
        //            // TODO error code?
        //            return false;

        //        Org.BouncyCastle.Crypto.ISigner signer = Org.BouncyCastle.Security.SignerUtilities.GetSigner("SHA256withRSA");

        //        RSACryptoServiceProvider key = certPub.PublicKey.Key as RSACryptoServiceProvider;
        //        if (key == null)
        //        {
        //            throw new SignatureUtilsException("Exception occurred while reading public certificate");
        //        }

        //        RSAParameters parameters = key.ExportParameters(false);
        //        Org.BouncyCastle.Math.BigInteger exponent = new Org.BouncyCastle.Math.BigInteger(parameters.Exponent);
        //        Org.BouncyCastle.Math.BigInteger modulus = new Org.BouncyCastle.Math.BigInteger(certPub.GetPublicKeyString(), 16);//parameters.Modulus);

        //        Org.BouncyCastle.Crypto.ICipherParameters clave = new Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters(false, modulus, exponent);

        //        signer.Init(false, clave);

        //        /* Get the signature into bytes */
        //        XmlElement expectedSig = (XmlElement)nodeList[0];

        //        /* Get the bytes to be signed from the string */
        //        XmlElement xmlAux = el;
        //        XmlNode nodeToDelete = xmlAux.GetElementsByTagName("Signature", XMLDSIG)[0];

        //        xmlAux.GetElementsByTagName("Signature", XMLDSIG)[0].ParentNode.RemoveChild(nodeToDelete);

        //        var msgBytes = Encoding.UTF8.GetBytes(xmlAux.OuterXml);

        //        /* Calculate the signature and see if it matches */
        //        signer.BlockUpdate(msgBytes, 0, msgBytes.Length);

        //        return signer.VerifySignature(Encoding.Default.GetBytes(expectedSig.OuterXml));

        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.Error(e);
        //        throw new SignatureUtilsException("Exception occurred on SignatureUtils.VerifySignature", ex);
        //    }
        //}


        /// <summary>
        /// Given a certificate, this method verifies if the signature within an xml document is valid or not
        /// https://msdn.microsoft.com/es-es/library/ms229950(v=vs.110).aspx
        /// Usando  System.Security.Cryptography.Xml en lugar de  Org.BouncyCastle.Crypto
        /// </summary>
        /// <param name="el">an xml document element</param>
        /// <param name="certPub">a certificate containing the public key to be used on the signature</param>
        /// <returns>true if the signature is valid; else otherwise</returns>
        public static bool VerifySignature(XmlElement el, X509Certificate2 certPub)
        {
            try
            {
                //Clave
                RSACryptoServiceProvider key = certPub.PublicKey.Key as RSACryptoServiceProvider;

                SignedXml signedXml = new SignedXml(el);
                XmlNodeList nodeList = el.GetElementsByTagName("Signature", XMLDSIG);

                if (nodeList.Count == 0) // Document does not contain a signature to verify
                    // TODO error code?
                    return false;

                signedXml.LoadXml((XmlElement)nodeList[0]);
                return signedXml.CheckSignature(key);
            }
            catch (Exception ex)
            {
                _logger.Error(ex);
                throw new SignatureUtilsException("Exception occurred on SignatureUtils.VerifySignature", ex);
            }
        }

        /// <summary>
        /// Verifies if a signature within an xml element is valid
        /// </summary>
        /// <param name="doc">an xml document with a signature element</param>
        /// <returns>true if the signature is valid; false otherwise</returns>
        /*      public static bool VerifySignature(XmlElement element, X509Certificate2 certPub, bool flag) {
                  CryptoConfig.AddAlgorithm(typeof(RsaPkCs1Sha256SignatureDescription), @"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

                  var cspParams = new CspParameters(24) { KeyContainerName = "XML_DISG_RSA_KEY" };
                  var key = new RSACryptoServiceProvider(cspParams);
                  key.FromXmlString(_x509SecurityToken.Certificate.PrivateKey.ToXmlString(true));

                  var signer = new SoapSignedXml(doc) { SigningKey = key };

                  signer.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

                  var keyInfo = new KeyInfo();
                  keyInfo.AddClause(new SecurityTokenReference(_x509SecurityToken, SecurityTokenReference.SerializationOptions.Embedded));

                  signer.KeyInfo = keyInfo;
                  signer.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

                  var cn14Transform = new XmlDsigExcC14NTransform();
                  string referenceDigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";

                  foreach (string id in idsToSign) {
                      var reference = new Reference("#" + id);
                      reference.AddTransform(cn14Transform);
                      reference.DigestMethod = referenceDigestMethod;
                      signer.AddReference(reference);
                  }

                  signer.ComputeSignature();
              }
              */

        /// <summary> 
        /// Signs an xml document and attaches the signature element after the reference node.
        /// </summary>
        /// <param name="doc">an xml document to be signed</param>
        /// <param name="cert">a certificate containing a private key</param>
        /// <param name="refNode">the reference node, the signature will be attached after it</param>
        public static void SignDocument(XmlDocument doc, X509Certificate2 cert, XmlNode refNode)
        {
            try
            {
                SignDocument(doc, "", cert, refNode);
            }
            catch (Exception ex)
            {
                _logger.Error(ex);
                throw new SignatureUtilsException("Exception occurred on SignatureUtils.SignDocument", ex);
            }
        }

        /// <summary> 
        /// Signs an xml element and attaches the signature element after the reference node.
        /// </summary>
        /// <param name="doc">an xml document to be signed</param>
        /// <param name="cert">a certificate containing a private key</param>
        /// <param name="refNode">the reference node, the signature will be attached after it</param>
        public static void SignDocument(XmlElement element, X509Certificate2 cert, XmlNode refNode)
        {
            try
            {
                SignDocument(element, "", cert, refNode);
            }
            catch (Exception ex)
            {
                _logger.Error(ex);
                throw new SignatureUtilsException("Exception occurred on SignatureUtils.SignDocument", ex);
            }
        }

        /// <summary>
        /// Signs an xml document with a given id and attaches the signature after
        /// a given reference node.
        /// </summary>
        /// <param name="doc">an xml document</param>
        /// <param name="id">the id of an element to be signed</param>
        /// <param name="cert">a certificate with a private key</param>
        /// <param name="refNode">a reference node</param>
        public static void SignDocument(XmlDocument doc, string id, X509Certificate2 cert, XmlNode refNode)
        {
            try
            {
                SignDocument(doc.DocumentElement, id, cert, refNode);
            }
            catch (Exception ex)
            {
                _logger.Error(ex);
                throw new SignatureUtilsException("Exception occurred on SignatureUtils.SignDocument", ex);
            }
        }

        /// <summary>
        /// Signs an xml document with a given id and attaches the signature after
        /// a given reference node.
        /// </summary>
        /// <param name="doc">an xml document</param>
        /// <param name="id">the id of an element to be signed</param>
        /// <param name="cert">a certificate with a private key</param>
        /// <param name="refNode">a reference node</param>
        public static void SignDocument(XmlElement element, string id, X509Certificate2 cert, XmlNode refNode)
        {
            try
            {
                SignedXml signedXml = new SignedXml(element);
                signedXml.SigningKey = cert.PrivateKey;

                Reference reference = new Reference(id == String.Empty ? id : "#" + id);
                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                reference.AddTransform(new XmlDsigExcC14NTransform());
                signedXml.AddReference(reference);
                signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert));
                signedXml.ComputeSignature();
                XmlElement xmlDigitalSignature = signedXml.GetXml();
                element.InsertAfter(xmlDigitalSignature, refNode);

            }
            catch (Exception ex)
            {
                _logger.Error(ex);
                throw new SignatureUtilsException("Exception occurred on SignatureUtils.SignDocument", ex);
            }
        }

    }
}
