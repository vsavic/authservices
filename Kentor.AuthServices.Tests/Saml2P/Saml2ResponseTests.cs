﻿using FluentAssertions;
using Kentor.AuthServices.Configuration;
using Kentor.AuthServices.TestHelpers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System.IdentityModel.Services;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.IO;
using Kentor.AuthServices.Internal;
using Kentor.AuthServices.Saml2P;
using System.Deployment.Internal.CodeSigning;

namespace Kentor.AuthServices.Tests.Saml2P
{
    [TestClass]
    public class Saml2ResponseTests
    {
        [TestMethod]
        public void Saml2Response_Read_BasicParams()
        {
            string response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
                <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Read_BasicParams"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            InResponseTo = ""InResponseToId""
            Destination=""http://destination.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            var expected = new
            {
                Id = new Saml2Id("Saml2Response_Read_BasicParams"),
                IssueInstant = new DateTime(2013, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                Status = Saml2StatusCode.Requester,
                Issuer = new EntityId(null),
                DestinationUrl = new Uri("http://destination.example.com"),
                MessageName = "SAMLResponse",
                InResponseTo = new Saml2Id("InResponseToId"),
                RequestState = (StoredRequestState)null,
            };

            Saml2Response.Read(response).ShouldBeEquivalentTo(expected,
                opt => opt.Excluding(s => s.XmlDocument));
        }

        [TestMethod]
        public void Saml2Response_Read_ThrowsOnNonXml()
        {
            Action a = () => Saml2Response.Read("not xml");

            a.ShouldThrow<XmlException>();
        }

        [TestMethod]
        public void Saml2Response_Read_ThrowsWrongRootNodeName()
        {
            Action a = () => Saml2Response.Read("<saml2p:NotResponse xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" />");

            a.ShouldThrow<XmlException>()
                .WithMessage("Expected a SAML2 assertion document");
        }

        [TestMethod]
        public void Saml2Response_Read_ThrowsWrongRootNamespace()
        {
            Action a = () => Saml2Response.Read("<saml2p:Response xmlns:saml2p=\"something\" /> ");
            a.ShouldThrow<XmlException>()
                .WithMessage("Expected a SAML2 assertion document");
        }

        [TestMethod]
        public void Saml2Response_Read_ThrowsOnWrongVersion()
        {
            Action a = () => Saml2Response.Read("<saml2p:Response xmlns:saml2p=\""
                + Saml2Namespaces.Saml2P + "\" Version=\"wrong\" />");

            a.ShouldThrow<XmlException>()
                .WithMessage("Wrong or unsupported SAML2 version");

        }

        [TestMethod]
        public void Saml2Response_Read_Issuer()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Respons_Read_Issuer"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
            <saml2:Issuer>
                https://some.issuer.example.com
            </saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            Saml2Response.Read(response).Issuer.Id.Should().Be("https://some.issuer.example.com");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowOnMissingSignatureInResponseAndAnyAssertion()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_FalseOnMissingSignatureInResponseAndAnyAssertion"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_FalseOnMissingSignatureInResponseAndAnyAssertion_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_FalseOnMissingSignatureInResponseAndAnyAssertion_Assertion2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            Action a = () => Saml2Response.Read(response).GetClaims(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("The SAML Response is not signed and contains unsigned Assertions. Response cannot be trusted.");
        }

        [TestMethod]
        [NotReRunnable]
        public void Saml2Response_GetClaims_CorrectSignedResponseMessage()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_TrueOnCorrectSignedResponseMessage"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_TrueOnCorrectSignedResponseMessage_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var signedResponse = SignedXmlHelper.SignXml(response);

            Action a = () => Saml2Response.Read(signedResponse).GetClaims(Options.FromConfiguration);
            a.ShouldNotThrow();
        }

        [TestMethod]
        [Ignore]
        public void Saml2Response_GetClaims_CorrectSignedSingleAssertionInResponseMessage()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_TrueOnCorrectSignedSingleAssertionInResponseMessage"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                {0}
            </saml2p:Response>";

            var assertion =
            @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_TrueOnCorrectSignedSingleAssertionInResponseMessagee_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";


            var signedAssertion = SignedXmlHelper.SignXml(assertion);
            var signedResponse = string.Format(response, signedAssertion);

            Action a = () => Saml2Response.Read(signedResponse).GetClaims(Options.FromConfiguration);
            a.ShouldNotThrow();
        }


        [TestMethod]
        public void Saml2Response_GetClaims_CorrectSignedSingleAssertionWithKeyInfoInResponseMessage()
        {
            var RsaSha256Namespace = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            CryptoConfig.AddAlgorithm( typeof( RSAPKCS1SHA256SignatureDescription ), RsaSha256Namespace );

            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_TrueOnCorrectSignedSingleAssertionInResponseMessage"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                {0}
            </saml2p:Response>";

            var assertion = new Saml2Assertion( new Saml2NameIdentifier( "https://idp.example.com" ) );
            assertion.Subject = new Saml2Subject( new Saml2NameIdentifier( "SomeUser" ) );
            assertion.Subject.SubjectConfirmations.Add( new Saml2SubjectConfirmation( new Uri( "urn:oasis:names:tc:SAML:2.0:cm:bearer" ) ) );
            assertion.Conditions = new Saml2Conditions() { NotOnOrAfter = new DateTime( 2100, 1, 1 ) };

            var signedAssertion = SignedXmlHelper.SignAssertion( assertion );
            var signedResponse = string.Format( response, signedAssertion );

            File.WriteAllText(@"C:\dev\wif_sha256.xml", signedResponse);

            Action a = () => Saml2Response.Read( signedResponse ).GetClaims( Options.FromConfiguration );
            a.ShouldNotThrow();
        }

        [TestMethod]
        [Ignore]
        public void Saml2Response_GetClaims_CorrectSignedMultipleAssertionInResponseMessage()
        {
            var response= 
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_TrueOnCorrectSignedMultipleAssertionInResponseMessage"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                {0}
                {1}
            </saml2p:Response>";

            var assertion1 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_TrueOnCorrectSignedMultipleAssertionInResponseMessage_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var assertion2 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_TrueOnCorrectSignedMultipleAssertionInResponseMessage_Assertion2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser2</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";


            var signedAssertion1 = SignedXmlHelper.SignXml(assertion1);
            var signedAssertion2 = SignedXmlHelper.SignXml(assertion2);
            var signedResponse = string.Format(response, signedAssertion1, signedAssertion2);

            Action a = () => Saml2Response.Read(signedResponse).GetClaims(Options.FromConfiguration);
            a.ShouldNotThrow();
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnMultipleAssertionInUnsignedResponseMessageButNotAllSigned()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_FalseOnMultipleAssertionInUnsignedResponseMessageButNotAllSigned"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                {0}
                {1}
            </saml2p:Response>";

            var assertion1 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_FalseOnMultipleAssertionInUnsignedResponseMessageButNotAllSigned_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var assertion2 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_FalseOnMultipleAssertionInUnsignedResponseMessageButNotAllSigned_Assertion2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser2</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";


            var signedAssertion1 = SignedXmlHelper.SignXml(assertion1);
            var signedResponse = string.Format(response, signedAssertion1, assertion2);

            Action a = () => Saml2Response.Read(signedResponse).GetClaims(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("The SAML Response is not signed and contains unsigned Assertions. Response cannot be trusted.");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnTamperedAssertionWithMessageSignature()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_FalseOnTamperedAssertionWithMessageSignature"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_FalseOnTamperedAssertionWithMessageSignature_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var signedResponse = SignedXmlHelper.SignXml(response).Replace("SomeUser", "SomeOtherUser");

            Action a = () => Saml2Response.Read(signedResponse).GetClaims(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Signature validation failed on SAML response or contained assertion.");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnTamperedAssertionWithAssertionSignature()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_FalseOnTamperedAssertionWithAssertionSignature"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                {0}
                {1}
            </saml2p:Response>";

            var assertion1 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_FalseOnTamperedAssertionWithAssertionSignature_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var assertion2 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_FalseOnTamperedAssertionWithAssertionSignature_Assertion2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser2</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var signedAssertion1 = SignedXmlHelper.SignXml(assertion1);
            var signedAssertion2 = SignedXmlHelper.SignXml(assertion2).Replace("SomeUser2", "SomeOtherUser");
            var signedResponse = string.Format(response, signedAssertion1, signedAssertion2);

            Action a = () => Saml2Response.Read(signedResponse).GetClaims(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Signature validation failed on SAML response or contained assertion.");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnAssertionInjectionWithAssertionSignature()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_FalseOnAssertionInjectionWithAssertionSignature"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                {0}
                {1}
            </saml2p:Response>";

            var assertion1 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_FalseOnAssertionInjectionWithAssertionSignature_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var assertionToInject = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_FalseOnAssertionInjectionWithAssertionSignature_Assertion2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser2</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var signedAssertion1 = SignedXmlHelper.SignXml(assertion1);

            var signedAssertion1Doc = new XmlDocument { PreserveWhitespace = true };
            signedAssertion1Doc.LoadXml(signedAssertion1);

            var signatureToCopy = signedAssertion1Doc.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl];

            var assertionToInjectDoc = new XmlDocument { PreserveWhitespace = true };
            assertionToInjectDoc.LoadXml(assertionToInject);

            assertionToInjectDoc.DocumentElement.AppendChild(assertionToInjectDoc.ImportNode(signatureToCopy, true));

            var signedAssertionToInject = assertionToInjectDoc.OuterXml;

            var signedResponse = string.Format(response, signedAssertion1, signedAssertionToInject);

            Action a = () => Saml2Response.Read(signedResponse).GetClaims(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Incorrect reference on Xml signature. The reference must be to the root element of the element containing the signature.");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnDualReferencesInSignature()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_ThrowsOnDualReferences"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""Saml2Response_GetClaims_ThrowsOnDualReferences1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(response);

            var signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = (RSACryptoServiceProvider)SignedXmlHelper.TestCert.PrivateKey;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            var ref1 = new Reference { Uri = "#Saml2Response_GetClaims_ThrowsOnDualReferences" };
            ref1.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            ref1.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(ref1);

            var ref2 = new Reference { Uri = "#Saml2Response_GetClaims_ThrowsOnDualReferences" };
            ref2.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            ref2.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(ref2);

            signedXml.ComputeSignature();
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(signedXml.GetXml(), true));

            Action a = () => Saml2Response.Read(xmlDoc.OuterXml).GetClaims(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Multiple references for Xml signatures are not allowed.");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnIncorrectTransformsInSignature()
        {
            // SAML2 Core 5.4.4 states that signatures SHOULD NOT contain other transforms than
            // the enveloped signature or exclusive canonicalization transforms and that a verifier
            // of a signature MAY reject signatures with other transforms. We'll reject them to
            // mitigate the risk of transforms opening up for assertion injections.

            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_FalseOnAdditionalTransformsInSignature"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(response);

            var signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = (RSACryptoServiceProvider)SignedXmlHelper.TestCert.PrivateKey;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            var reference = new Reference { Uri = "#Saml2Response_GetClaims_FalseOnAdditionalTransformsInSignature" };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigC14NTransform()); // The allowed transform is XmlDsigExcC14NTransform
            signedXml.AddReference(reference);

            signedXml.ComputeSignature();
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(signedXml.GetXml(), true));

            Action a = () => Saml2Response.Read(xmlDoc.OuterXml).GetClaims(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Transform \"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" found in XML signature is not allowed in SAML.");
        }

        [TestMethod]
        public void Saml2Response_Validate_ThrowsOnMissingReferenceInSignature()
        {
            var signedWithoutReference = @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""Saml2Response_Validate_FalseOnMissingReference"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""><saml2:Issuer>https://idp.example.com</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" /></saml2p:Status><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315"" /><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1"" /></SignedInfo><SignatureValue>tYFIoYmrzmp3H7TXm9IS8DW3buBZIb6sI2ycrn+AOnVcdYnPTJpk3ntHlqQKXNEyXgXZNdqEuFpgI1I0P0TlhM+C3rBJnflkApkxZkak5RwnJzDWTHpsSDjYcm+/XgBy3JVZJuMWb2YPaV8GB6cjBMDrENUEaoKRg+FpzPUZO1EOMcqbocXp5cHie1CkPnD1OtT/cuzMBUMpBGZMxjZwdFpOO7R3CUXh/McxKfoGUQGC3DVpt5T8uGkpj4KqZVPS/qTCRhbPRDjg73BdWbdkFpFWge8G/FgkYxr9LBE1TsrxptppO9xoA5jXwJVZaWndSMvo6TuOjUgqY2w5RTkqhA==</SignatureValue></Signature></saml2p:Response>";

            var samlResponse = Saml2Response.Read(signedWithoutReference);

            Action a = () => samlResponse.GetClaims(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("No reference found in Xml signature, it doesn't validate the Xml data.");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ReturnsExistingResultOnSecondGetClaimsCall()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_TrueOnCorrectSignedResponseMessage"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
            </saml2p:Response>";

            var signedResponse = SignedXmlHelper.SignXml(response);

            var samlResponse = Saml2Response.Read(signedResponse);

            Action a = () => samlResponse.GetClaims(Options.FromConfiguration);

            a.ShouldNotThrow();
            a.ShouldNotThrow();
        }

        [NotReRunnable]
        [TestMethod]
        public void Saml2Response_GetClaims_CreateIdentities()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_CreateIdentities"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_CreateIdentities1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_CreateIdentities2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeOtherUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var c1 = new ClaimsIdentity("Federation");
            c1.AddClaim(new Claim(ClaimTypes.NameIdentifier, "SomeUser", null, "https://idp.example.com"));
            var c2 = new ClaimsIdentity("Federation");
            c2.AddClaim(new Claim(ClaimTypes.NameIdentifier, "SomeOtherUser", null, "https://idp.example.com"));

            var expected = new ClaimsIdentity[] { c1, c2 };

            var r = Saml2Response.Read(SignedXmlHelper.SignXml(response));

            r.GetClaims(StubFactory.CreateOptions())
                .ShouldBeEquivalentTo(expected, opt => opt.IgnoringCyclicReferences());
        }

        [TestMethod]
        [NotReRunnable]
        public void Saml2Response_GetClaims_SavesBootstrapContext()
        {
            var assertion = 
            @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_SavesBootstrapContext_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2:Subject>
                    <saml2:NameID>SomeUser</saml2:NameID>
                    <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                </saml2:Subject>
                <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
            </saml2:Assertion>";

            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_SavesBootstrapContext"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>"
            + assertion +
            "</saml2p:Response>";

            var options = StubFactory.CreateOptions();

            options.SPOptions.Saml2PSecurityTokenHandler.Configuration.SaveBootstrapContext = true;

            var expected = options.SPOptions.Saml2PSecurityTokenHandler.ReadToken(XmlReader.Create(new StringReader(assertion)));

            var r = Saml2Response.Read(SignedXmlHelper.SignXml(response));

            var subject = r.GetClaims(options).Single().BootstrapContext;

            subject.As<BootstrapContext>().SecurityToken.ShouldBeEquivalentTo(expected);
        }

        [TestMethod]
        public void Saml2Response_GetRequestState_ThrowsOnResponseNotValid()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_ThrowsOnResponseNotValid"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""Saml2Response_GetClaims_ThrowsOnResponseNotValid_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                </saml2:Assertion>
            </saml2p:Response>";

            response = SignedXmlHelper.SignXml(response);
            response = response.Replace("2013-09-25", "2013-09-26");

            var r = Saml2Response.Read(response);

            Action a = () => r.GetRequestState(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Signature validation failed on SAML response or contained assertion.");

            // Test that it throws again on subsequent calls.
            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Signature validation failed on SAML response or contained assertion.");
        }

        [NotReRunnable]
        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnWrongAudience()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_ThrowsOnWrongAudience"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""Saml2Response_GetClaims_ThrowsOnWrongAudience_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" >
                        <saml2:AudienceRestriction>
                            <saml2:Audience>https://example.com/wrong/audience</saml2:Audience>
                        </saml2:AudienceRestriction>
                    </saml2:Conditions>
                </saml2:Assertion>
            </saml2p:Response>";

            response = SignedXmlHelper.SignXml(response);

            var r = Saml2Response.Read(response);

            Action a = () => r.GetClaims(Options.FromConfiguration);

            a.ShouldThrow<AudienceUriValidationFailedException>();
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnExpired()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_ThrowsOnExpired"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""Saml2Response_GetClaims_ThrowsOnExpired_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2013-06-30T08:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            response = SignedXmlHelper.SignXml(response);
            var r = Saml2Response.Read(response);

            Action a = () => r.GetClaims(Options.FromConfiguration);

            a.ShouldThrow<SecurityTokenExpiredException>();
        }

        [TestMethod]
        public void Saml2Response_GetClaims_CorrectInResponseTo()
        {
            var idp = Options.FromConfiguration.IdentityProviders.Default;

            var request = idp.CreateAuthenticateRequest(null, StubFactory.CreateAuthServicesUrls());

            var responseXML =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_TrueOnCorrectInResponseTo"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            InResponseTo = """ + request.Id + @""">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
            </saml2p:Response>";

            responseXML = SignedXmlHelper.SignXml(responseXML);

            var response = Saml2Response.Read(responseXML);

            Action a = () => response.GetClaims(Options.FromConfiguration);
            a.ShouldNotThrow();
        }

        [TestMethod]
        public void Saml2Response_GetClaims_FalseOnMissingInResponseTo_IfDisallowed()
        {
            var responseXML =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_FalseOnMissingInResponseTo_IfDisallowed"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp2.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            responseXML = SignedXmlHelper.SignXml(responseXML);

            var response = Saml2Response.Read(responseXML);

            Action a = () => response.GetClaims(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Unsolicited responses are not allowed for idp \"https://idp2.example.com\".");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_MissingInResponseTo_IfAllowed()
        {
            var idp = Options.FromConfiguration.IdentityProviders.Default;

            var request = idp.CreateAuthenticateRequest(null, StubFactory.CreateAuthServicesUrls());

            var responseXML =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_TrueOnCorrectInResponseTo"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
            </saml2p:Response>";

            responseXML = SignedXmlHelper.SignXml(responseXML);

            var response = Saml2Response.Read(responseXML);

            Action a = () => response.GetClaims(Options.FromConfiguration);
            a.ShouldNotThrow();
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnIncorrectInResponseTo()
        {
            var idp = Options.FromConfiguration.IdentityProviders.Default;

            var request = idp.CreateAuthenticateRequest(null, StubFactory.CreateAuthServicesUrls());

            var responseXML =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_FalseOnIncorrectInResponseTo"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            InResponseTo = ""anothervalue"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            responseXML = SignedXmlHelper.SignXml(responseXML);

            var response = Saml2Response.Read(responseXML);

            Action a = () => response.GetClaims(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Replayed or unknown InResponseTo \"anothervalue\".");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnReplayedInResponseTo()
        {
            var idp = Options.FromConfiguration.IdentityProviders.Default;

            var request = idp.CreateAuthenticateRequest(null, StubFactory.CreateAuthServicesUrls());

            var responseXML =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_ThrowsOnReplayedInResponseTo"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            InResponseTo = """ + request.Id + @""">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
            </saml2p:Response>";

            responseXML = SignedXmlHelper.SignXml(responseXML);

            Action a = () =>
            {
                var response = Saml2Response.Read(responseXML);
                response.GetClaims(Options.FromConfiguration);
            };

            a.ShouldNotThrow();
            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Replayed or unknown InResponseTo \"" + request.Id + "\".");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnTamperedMessage()
        {
            var idp = Options.FromConfiguration.IdentityProviders.Default;

            var request = idp.CreateAuthenticateRequest(null, StubFactory.CreateAuthServicesUrls());

            var responseXML =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_ThrowsOnReplayedInResponseTo"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            InResponseTo = """ + request.Id + @""">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            responseXML = SignedXmlHelper.SignXml(responseXML);
            responseXML = responseXML.Replace("2013-01-01", "2015-01-01"); // Break signature.

            var response = Saml2Response.Read(responseXML);

            Action a = () =>
            {
                response.GetClaims(Options.FromConfiguration);
            };

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Signature validation failed on SAML response or contained assertion.");

            // With an incorrect signature, a signature validation should be
            // thrown - even if we response is validate twice. In case
            // GetClaims/Validate doesn't cache the result it will instead
            // report a replay exception the second time because the replay
            // detection is done before the signature validation.

            a.ShouldThrow<Saml2ResponseFailedValidationException>()
                .WithMessage("Signature validation failed on SAML response or contained assertion.");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnResponseFromWrongIdp()
        {
            // A valid response is received, but it is not from the idp that we
            // did send the AuthnRequest to.
            var idp = Options.FromConfiguration.IdentityProviders.Default;

            var request = idp.CreateAuthenticateRequest(null, StubFactory.CreateAuthServicesUrls());

            var responseXML =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_ThrowsOnResponseFromWrongIdp"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            InResponseTo = """ + request.Id + @""">
                <saml2:Issuer>https://idp.anotheridp.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            responseXML = SignedXmlHelper.SignXml(responseXML);

            var response = Saml2Response.Read(responseXML);

            Action a = () => response.GetClaims(Options.FromConfiguration);

            a.ShouldThrow<Saml2ResponseFailedValidationException>().And
                .Message.Should().Be("Expected response from idp \"https://idp.example.com\" but received response from idp \"https://idp.anotheridp.com\".");
        }

        [TestMethod]
        [NotReRunnable]
        public void Saml2Response_GetClaims_ThrowsOnReplayAssertionId()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_ThrowsOnReplayAssertionId"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""Saml2Response_GetClaims_ThrowsOnReplayAssertionId_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            response = SignedXmlHelper.SignXml(response);
            var r1 = Saml2Response.Read(response);
            r1.GetClaims(Options.FromConfiguration);

            var r2 = Saml2Response.Read(response);

            Action a = () => r2.GetClaims(Options.FromConfiguration);

            a.ShouldThrow<SecurityTokenReplayDetectedException>();
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnStatusFailure()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_GetClaims_ThrowsOnStatusFailure"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""Saml2Response_GetClaims_ThrowsOnStatusFailure_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var xml = SignedXmlHelper.SignXml(response);

            var subject = Saml2Response.Read(xml);

            Action a = () => subject.GetClaims(Options.FromConfiguration);

            a.ShouldThrow<InvalidOperationException>()
                .WithMessage("The Saml2Response must have status success to extract claims.");

        }

        [TestMethod]
        public void Saml2Response_Ctor_FromData()
        {
            var issuer = new EntityId("http://idp.example.com");
            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.NameIdentifier, "JohnDoe") 
            });
            var response = new Saml2Response(issuer, null, null, null, identity);

            response.Issuer.Should().Be(issuer);
            response.GetClaims(Options.FromConfiguration)
                .Single()
                .ShouldBeEquivalentTo(identity);
        }

        [TestMethod]
        public void Saml2Response_Xml_FromData_ContainsBasicData()
        {
            var issuer = new EntityId("http://idp.example.com");
            var nameId = "JohnDoe";
            var destination = "http://destination.example.com/";

            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.NameIdentifier, nameId) 
            });

            // Grab current time both before and after generating the response
            // to avoid heisenbugs if the second counter is updated while creating
            // the response.
            string before = DateTime.UtcNow.ToSaml2DateTimeString();
            var response = new Saml2Response(issuer, SignedXmlHelper.TestCert,
                new Uri(destination), null, identity);
            string after = DateTime.UtcNow.ToSaml2DateTimeString();

            var xml = response.XmlDocument;

            xml.FirstChild.OuterXml.Should().StartWith("<?xml version=\"1.0\"");
            xml.DocumentElement["Issuer", Saml2Namespaces.Saml2Name].InnerText.Should().Be(issuer.Id);
            xml.DocumentElement["Assertion", Saml2Namespaces.Saml2Name]
                ["Subject", Saml2Namespaces.Saml2Name]["NameID", Saml2Namespaces.Saml2Name]
                .InnerText.Should().Be(nameId);
            xml.DocumentElement.GetAttribute("Destination").Should().Be(destination);
            xml.DocumentElement.GetAttribute("ID").Should().NotBeNullOrWhiteSpace();
            xml.DocumentElement.GetAttribute("Version").Should().Be("2.0");
            xml.DocumentElement.GetAttribute("IssueInstant").Should().Match(
                i => i == before || i == after);
        }

        [TestMethod]
        public void Saml2Response_Xml_FromData_ContainsStatus_Success()
        {
            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.NameIdentifier, "JohnDoe") 
            });

            var response = new Saml2Response(new EntityId("issuer"), SignedXmlHelper.TestCert,
                new Uri("http://destination.example.com"), null, identity);

            var xml = response.XmlDocument;

            var subject = xml.DocumentElement["Status", Saml2Namespaces.Saml2PName];

            subject["StatusCode", Saml2Namespaces.Saml2PName].GetAttribute("Value")
                .Should().Be("urn:oasis:names:tc:SAML:2.0:status:Success");
        }

        [TestMethod]
        public void Saml2Response_Xml_FromData_ContainsInResponseTo()
        {
            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.NameIdentifier, "JohnDoe") 
            });

            var response = new Saml2Response(new EntityId("issuer"), SignedXmlHelper.TestCert,
                new Uri("http://destination.example.com"), "InResponseToID", identity);

            var xml = response.XmlDocument;

            xml.DocumentElement.GetAttribute("InResponseTo").Should().Be("InResponseToID");
        }

        [TestMethod]
        public void Saml2Response_Xml_FromData_IsSigned()
        {
            var issuer = new EntityId("http://idp.example.com");
            var nameId = "JohnDoe";
            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.NameIdentifier, nameId) 
            });

            var response = new Saml2Response(issuer, SignedXmlHelper.TestCert,
                null, null, claimsIdentities: identity);

            var xml = response.XmlDocument;

            var signedXml = new SignedXml(xml);
            var signature = xml.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl];
            signedXml.LoadXml(signature);

            signature.Should().NotBeNull();

            signedXml.CheckSignature(SignedXmlHelper.TestCert, true).Should().BeTrue();
        }

        [TestMethod]
        public void Saml2Response_ToXml()
        {
            string response = @"<?xml version=""1.0"" encoding=""UTF-8""?><saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""Saml2Response_ToXml"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""><saml2p:Status><saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" /></saml2p:Status></saml2p:Response>";

            var subject = Saml2Response.Read(response).ToXml();

            subject.Should().Be(response);
        }

        [TestMethod]
        public void Saml2Response_MessageName()
        {
            var subject = new Saml2Response(new EntityId("issuer"), null, null, null);

            subject.MessageName.Should().Be("SAMLResponse");
        }

        [TestMethod]
        public void Saml2Response_FromRequest_Remembers_ReturnUrl()
        {
            var idp = Options.FromConfiguration.IdentityProviders.Default;

            var request = idp.CreateAuthenticateRequest(new Uri("http://localhost/testUrl.aspx"), StubFactory.CreateAuthServicesUrls());

            var responseXML =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = ""Saml2Response_FromRequest_Remembers_ReturnUrl"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            InResponseTo = """ + request.Id + @""">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            responseXML = SignedXmlHelper.SignXml(responseXML);

            var response = Saml2Response.Read(responseXML);

            response.GetRequestState(Options.FromConfiguration)
                .ReturnUrl.Should().Be("http://localhost/testUrl.aspx");
        }
    }
}
