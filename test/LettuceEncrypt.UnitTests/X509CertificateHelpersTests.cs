// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal;
using Xunit;

namespace LettuceEncrypt.UnitTests;

using static TestUtils;

public class X509CertificateHelpersTests
{
    [Fact]
    public void IsSelfSigned_WithSelfSignedCert_ReturnsTrue()
    {
        var cert = CreateTestCert("self-signed.example.com");

        Assert.True(cert.IsSelfSigned());
    }

    [Fact]
    public void GetCommonName_ReturnsCorrectName()
    {
        var cert = CreateTestCert("common-name.example.com");

        var commonName = X509CertificateHelpers.GetCommonName(cert);

        Assert.Equal("common-name.example.com", commonName);
    }

    [Fact]
    public void GetAllDnsNames_WithSingleCN_ReturnsOneName()
    {
        var cert = CreateTestCert("single.example.com");

        var dnsNames = X509CertificateHelpers.GetAllDnsNames(cert).ToList();

        Assert.Contains("single.example.com", dnsNames);
    }

    [Fact]
    public void GetAllDnsNames_WithSAN_ReturnsAllNames()
    {
        var domains = new[] { "primary.example.com", "secondary.example.com", "tertiary.example.com" };
        var cert = CreateTestCert(domains);

        var dnsNames = X509CertificateHelpers.GetAllDnsNames(cert).ToList();

        foreach (var domain in domains)
        {
            Assert.Contains(domain, dnsNames);
        }
    }

    [Fact]
    public void GetDnsFromExtensions_WithNoSAN_ReturnsEmpty()
    {
        var cert = CreateTestCert("no-san.example.com");

        var result = X509CertificateHelpers.GetDnsFromExtensions(cert);

        Assert.Empty(result);
    }

    [Fact]
    public void GetDnsFromExtensions_WithSAN_ReturnsDnsNames()
    {
        var domains = new[] { "primary.example.com", "alt1.example.com", "alt2.example.com" };
        var cert = CreateTestCert(domains);

        var result = X509CertificateHelpers.GetDnsFromExtensions(cert);

        // The SAN should contain the alt names (not the CN)
        Assert.Contains("alt1.example.com", result);
        Assert.Contains("alt2.example.com", result);
    }
}
