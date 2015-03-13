using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Kentor.AuthServices;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System;
using System.IO;
using System.Deployment.Internal.CodeSigning;

namespace Kentor.AuthServices.TestHelpers
{
    public class SignedXmlHelper
    {
        public static readonly X509Certificate2 TestCert = new X509Certificate2( "Kentor.AuthServices.Tests.pfx", (string)null, X509KeyStorageFlags.Exportable );

        public static readonly SigningCredentials SigningCredentials;

        public static readonly AsymmetricAlgorithm TestKey = TestCert.PublicKey.Key;

        public static readonly KeyDescriptor TestKeyDescriptor = new KeyDescriptor(
            new SecurityKeyIdentifier(
                (new X509SecurityToken(TestCert))
                .CreateKeyIdentifierClause<X509RawDataKeyIdentifierClause>()));

        public static string SignXml(string xml)
        {
            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.LoadXml(xml);

            xmlDoc.Sign(TestCert);

            return xmlDoc.OuterXml;
        }

        public static readonly string KeyInfoXml;

        public static string SignAssertion(Saml2Assertion assertion)
        {
            string signedAssertion = String.Empty;
            var token = new Saml2SecurityToken(assertion);

            var handler = new Saml2SecurityTokenHandler();
            assertion.SigningCredentials = SigningCredentials;

            using (var stringWriter = new StringWriter())
            {
                using (var xmlWriter = XmlWriter.Create( stringWriter,
                    new XmlWriterSettings { OmitXmlDeclaration = true }))
                {
                    handler.WriteToken(xmlWriter, token);
                }
                signedAssertion = stringWriter.ToString();
            }
            return signedAssertion;
        }

        static SignedXmlHelper()
        {
            var RsaSha256Namespace = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            CryptoConfig.AddAlgorithm( typeof( RSAPKCS1SHA256SignatureDescription ), RsaSha256Namespace );

            // Note that this will return a Basic crypto provider, with only SHA-1 support
            var privKey = (RSACryptoServiceProvider)TestCert.PrivateKey;

            CspParameters cspParams = new CspParameters(24);
            cspParams.KeyContainerName = "XML_DISG_RSA_KEY";
            RSACryptoServiceProvider key = new RSACryptoServiceProvider(cspParams);
            key.FromXmlString(TestCert.PrivateKey.ToXmlString(true));
            TestCert.PrivateKey = key;

            SigningCredentials = new X509SigningCredentials( TestCert,
                SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest );

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(TestCert));

            KeyInfoXml = keyInfo.GetXml().OuterXml;
        }

    }
}
