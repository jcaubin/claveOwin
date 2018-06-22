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

using System.Security.Cryptography.X509Certificates;
using System.Xml;

using eu.stork.peps.auth.commons.Exceptions;
using System.Threading;
using NLog;


//
// author: AMA – Agência para a Modernização Administrativa IP, PORTUGAL (www.ama.pt)
//
namespace eu.stork.peps.auth.commons
{
    /// <summary>
    /// Certificate related methods
    /// </summary>
    public class CertificateUtils
    {
        private static Logger _logger = LogManager.GetCurrentClassLogger();

        private const string KEY_MAX_STORED_CERTIF = "MaxNumberStoredCertificates";
        private const int MAX_STORED_CERTIF = 10;

        private static Dictionary<string, X509Certificate2> keystoreCache;
        private static List<string> keystoreCacheControl;
        private static int keystoreCacheIndex = 0;
        private static ReaderWriterLock rwl = new ReaderWriterLock();


        /// <summary>
        /// The XML namespace of XmlDSig
        /// </summary>
        public const string XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";

        static CertificateUtils()
        {
            int? capacity = ConfigurationSettingsHelper.GetConfigIntSetting(KEY_MAX_STORED_CERTIF);
            if (capacity == null) capacity = MAX_STORED_CERTIF;
            keystoreCache = new Dictionary<string, X509Certificate2>((int)capacity);
            keystoreCacheControl = new List<string>((int)capacity);
        }

        /// <summary>
        /// Get certificate from KeySotre, based on Thumbprint
        /// </summary>
        /// <param name="thumbprintOrCN"></param>
        /// <returns></returns>
        private static X509Certificate2 LookupKeystoreCache(string thumbprintOrCN)
        {
            rwl.AcquireReaderLock(-1);
            try
            {
                X509Certificate2 value;
                keystoreCache.TryGetValue(thumbprintOrCN, out value);
                return value;
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.LookupKeystoreCache: " + e.Message, e);
            }
            finally
            {
                rwl.ReleaseReaderLock();
            }
        }

        /// <summary>
        /// Puts certificate in local application cache
        /// </summary>
        /// <param name="thumbprintOrCN"></param>
        /// <param name="certificate"></param>
        private static void InsertKeystoreCache(string thumbprintOrCN, X509Certificate2 certificate)
        {
            rwl.AcquireWriterLock(-1);
            try
            {
                // remove
                string oldThumbprintOrCN = keystoreCacheControl.ElementAtOrDefault(keystoreCacheIndex);
                if (!string.IsNullOrEmpty(oldThumbprintOrCN))
                {
                    keystoreCache.Remove(oldThumbprintOrCN);
                    keystoreCacheControl.RemoveAt(keystoreCacheIndex);
                }

                // insert
                keystoreCache.Add(thumbprintOrCN, certificate);
                keystoreCacheControl.Insert(keystoreCacheIndex++, thumbprintOrCN);
                if (keystoreCacheIndex == keystoreCacheControl.Capacity)
                    keystoreCacheIndex = 0;
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.InsertKeystoreCache: " + e.Message, e);
            }
            finally
            {
                rwl.ReleaseWriterLock();
            }
        }

        /// <summary>
        /// Verifies if a given certificate is valid
        /// </summary>
        /// <param name="certificate">an X509 certificate</param>
        /// <returns>true if the certificate is valid; false otherwise</returns>
        public static bool IsCertificateValid(X509Certificate2 certificate)
        {
            try
            {
                //TODO logging

                var chain = new X509Chain();
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

                // ATTENTION CRLs not checked
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 1, 0);
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                return chain.Build(certificate);
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.IsCertificateValid: " + e.Message, e);
            }
        }

        /// <summary>
        /// Check if certificate is present in the local key store (address book)
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public static bool IsCertificateAllowed(X509Certificate2 certificate)
        {
            X509Store store = null;
            try
            {
                //TODO logging
                store = new X509Store(StoreName.AddressBook, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                return store.Certificates.Contains(certificate);
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.IsCertificateAllowed: " + e.Message, e);
            }
            finally
            {
                if (store != null)
                    store.Close();
            }

        }

        /// <summary>
        /// Retrieves a certificate from an xml document
        /// </summary>
        /// <param name="doc">an xml document</param>
        /// <returns>an X509 certificate</returns>
        public static X509Certificate2 RetrieveCertificate(XmlDocument doc)
        {
            try
            {
                //TODO logging
                string certificateB64 = doc.GetElementsByTagName("X509Certificate", XMLDSIG).
                    Item(0).InnerText;
                return new X509Certificate2(Convert.FromBase64String(certificateB64));
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.RetrieveCertificate: " + e.Message, e);
            }
        }

        /// <summary>
        /// Verifies if a certificate contained in an xml document is valid
        /// </summary>
        /// <param name="doc">an xml document</param>
        /// <returns>true if the certificate is valid; false otherwise</returns>
        public static bool VerifyCertificate(XmlDocument doc)
        {
            try
            {
                X509Certificate2 certificate = RetrieveCertificate(doc);
                return IsCertificateValid(certificate);
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.VerifyCertificate: " + e.Message, e);
            }
        }

        /// <summary>
        /// Gets a certificate from the local machine keystore
        /// </summary>
        /// <param name="commonName">thumbprint of the certificate</param>
        /// <param name="storeName">name of the store</param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateFromStoreByCN(string commonName, StoreName storeName)
        {
            X509Store store = null;
            X509Certificate2 cert = null;
            try
            {
                cert = LookupKeystoreCache(commonName);
                if (cert != null) return cert;

                store = new X509Store(storeName, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certCollection =
                    store.Certificates.Find(X509FindType.FindBySubjectName, commonName, false);
                X509Certificate2Enumerator enumerator = certCollection.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    cert = enumerator.Current;
                    if (cert.GetNameInfo(X509NameType.SimpleName, false).Equals(commonName))
                        break;
                    else
                        cert = null;
                }

                if (cert != null)
                    InsertKeystoreCache(commonName, cert);

                return cert;
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.GetCertificateFromStore: " + e.Message, e);
            }
            finally
            {
                if (store != null)
                    store.Close();
            }
        }

        /// <summary>
        /// Gets a certificate from the local machine keystore
        /// </summary>
        /// <param name="thumbprint">thumbprint of the certificate</param>
        /// <param name="storeName">name of the store</param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateFromStore(string thumbprint, StoreName storeName)
        {
            X509Store store = null;
            X509Certificate2 cert = null;
            try
            {
                //thumbprint = thumbprint.ToUpper();

                cert = LookupKeystoreCache(thumbprint);
                if (cert != null) return cert;

                store = new X509Store(storeName, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                cert = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)
                    .OfType<X509Certificate2>().FirstOrDefault();

                if (cert != null)
                    InsertKeystoreCache(thumbprint, cert);

                store.Close();
                return cert;
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.GetCertificateFromStore: " + e.Message, e);
            }
            finally
            {
                if (store != null)
                    store.Close();
            }
        }

        /// <summary>
        /// Gets a certificate from the local machine personal keystore
        /// </summary>
        /// <param name="thumbprint">thumbprint of the certificate</param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateFromPersonalStore(string thumbprint)
        {
            try
            {
                return GetCertificateFromStore(thumbprint, StoreName.My);
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.GetCertificateFromStore: " + e.Message, e);
            }
        }

        /// <summary>
        /// Gets a certificate from the local machine trusted CA keystore
        /// </summary>
        /// <param name="thumbprint">thumbprint of the certificate</param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateFromTrustedCAStore(string thumbprint)
        {
            try
            {
                return GetCertificateFromStore(thumbprint, StoreName.Root);
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.GetCertificateFromStore: " + e.Message, e);
            }
        }

        /// <summary>
        /// Gets a certificate from the local machine trusted CA keystore
        /// </summary>
        /// <param name="commonName">common name of the certificate</param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateFromTrustedCAStoreByCN(string commonName)
        {
            try
            {
                return GetCertificateFromStoreByCN(commonName, StoreName.Root);
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.GetCertificateFromStore: " + e.Message, e);
            }
        }

        /// <summary>
        /// Check the certificate Thumbprint against a predefined value
        /// </summary>
        /// <param name="cert">The certificate to compare</param>
        /// <param name="hexaThumbprint">Value to compare</param>
        /// <returns></returns>
        public static bool VerifyThumbprint(X509Certificate2 cert, string hexaThumbprint)
        {
            try
            {
                return cert.Thumbprint.ToUpper() == hexaThumbprint.ToUpper();
            }
            catch (Exception e)
            {
                _logger.Error(e);
                throw new CertificateUtilsException("Exception occurred on CertificateUtils.VerifyThumbprint: " + e.Message, e);
            }
        }
    }
}
