// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using LettuceEncrypt.Internal;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

using static TestUtils;

public class CertificateSelectorExtendedTests
{
    private CertificateSelector CreateSelector(LettuceEncryptOptions options = null)
    {
        return new CertificateSelector(
            Options.Create(options ?? new LettuceEncryptOptions()),
            NullLogger<CertificateSelector>.Instance);
    }

    [Fact]
    public void Select_WithNullDomainName_ReturnsFallbackCertificate()
    {
        var fallback = CreateTestCert("fallback.example.com");
        var selector = CreateSelector(new LettuceEncryptOptions
        {
            FallbackCertificate = fallback
        });

        var result = selector.Select(Mock.Of<ConnectionContext>(), null);

        Assert.Same(fallback, result);
    }

    [Fact]
    public void Select_WithUnknownDomain_ReturnsFallbackCertificate()
    {
        var fallback = CreateTestCert("fallback.example.com");
        var selector = CreateSelector(new LettuceEncryptOptions
        {
            FallbackCertificate = fallback
        });

        var result = selector.Select(Mock.Of<ConnectionContext>(), "unknown.example.com");

        Assert.Same(fallback, result);
    }

    [Fact]
    public void Select_WithNoFallback_ReturnsNull()
    {
        var selector = CreateSelector();

        var result = selector.Select(Mock.Of<ConnectionContext>(), "unknown.example.com");

        Assert.Null(result);
    }

    [Fact]
    public void Select_WithNullDomainAndNoFallback_ReturnsNull()
    {
        var selector = CreateSelector();

        var result = selector.Select(Mock.Of<ConnectionContext>(), null);

        Assert.Null(result);
    }

    [Fact]
    public void Select_WithKnownDomain_ReturnsCertificate()
    {
        var cert = CreateTestCert("known.example.com");
        var selector = CreateSelector();
        selector.Add(cert);

        var result = selector.Select(Mock.Of<ConnectionContext>(), "known.example.com");

        Assert.Same(cert, result);
    }

    [Fact]
    public void HasCertForDomain_ReturnsTrueForKnownDomain()
    {
        var cert = CreateTestCert("test.example.com");
        var selector = CreateSelector();
        selector.Add(cert);

        Assert.True(selector.HasCertForDomain("test.example.com"));
    }

    [Fact]
    public void HasCertForDomain_ReturnsFalseForUnknownDomain()
    {
        var selector = CreateSelector();

        Assert.False(selector.HasCertForDomain("unknown.example.com"));
    }

    [Fact]
    public void HasCertForDomain_WildcardMatchesSubdomain()
    {
        var cert = CreateTestCert("*.example.com");
        var selector = CreateSelector();
        selector.Add(cert);

        Assert.True(selector.HasCertForDomain("sub.example.com"));
    }

    [Fact]
    public void TryGet_ReturnsTrueForExactMatch()
    {
        var cert = CreateTestCert("exact.example.com");
        var selector = CreateSelector();
        selector.Add(cert);

        Assert.True(selector.TryGet("exact.example.com", out var result));
        Assert.Same(cert, result);
    }

    [Fact]
    public void TryGet_ReturnsFalseForMissing()
    {
        var selector = CreateSelector();

        Assert.False(selector.TryGet("missing.example.com", out var result));
        Assert.Null(result);
    }

    [Fact]
    public void TryGet_WildcardMatchesSubdomain()
    {
        var cert = CreateTestCert("*.example.com");
        var selector = CreateSelector();
        selector.Add(cert);

        Assert.True(selector.TryGet("sub.example.com", out var result));
        Assert.Same(cert, result);
    }

    [Fact]
    public void AddChallengeCert_SelectsChallengeCertOverRegular()
    {
        var regularCert = CreateTestCert("test.example.com");
        var challengeCert = CreateTestCert("test.example.com");
        var selector = CreateSelector();

        selector.Add(regularCert);
        selector.AddChallengeCert(challengeCert);

        var result = selector.Select(Mock.Of<ConnectionContext>(), "test.example.com");

        Assert.Same(challengeCert, result);
    }

    [Fact]
    public void ClearChallengeCert_FallsBackToRegularCert()
    {
        var regularCert = CreateTestCert("test.example.com");
        var challengeCert = CreateTestCert("test.example.com");
        var selector = CreateSelector();

        selector.Add(regularCert);
        selector.AddChallengeCert(challengeCert);
        selector.ClearChallengeCert("test.example.com");

        var result = selector.Select(Mock.Of<ConnectionContext>(), "test.example.com");

        Assert.Same(regularCert, result);
    }

    [Fact]
    public void Reset_RemovesCertForDomain()
    {
        var cert = CreateTestCert("test.example.com");
        var selector = CreateSelector();
        selector.Add(cert);

        Assert.NotNull(selector.Select(Mock.Of<ConnectionContext>(), "test.example.com"));

        selector.Reset("test.example.com");

        // After reset, the domain should no longer be found, returning null (no fallback)
        Assert.Null(selector.Select(Mock.Of<ConnectionContext>(), "test.example.com"));
    }

    [Fact]
    public void SupportedDomains_ReturnsAllAddedDomains()
    {
        var cert1 = CreateTestCert("domain1.example.com");
        var cert2 = CreateTestCert("domain2.example.com");
        var selector = CreateSelector();

        selector.Add(cert1);
        selector.Add(cert2);

        var domains = selector.SupportedDomains.ToList();
        Assert.Contains("domain1.example.com", domains);
        Assert.Contains("domain2.example.com", domains);
    }

    [Fact]
    public void Constructor_ThrowsOnNullOptions()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateSelector(null, NullLogger<CertificateSelector>.Instance));
    }

    [Fact]
    public void Constructor_ThrowsOnNullLogger()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateSelector(Options.Create(new LettuceEncryptOptions()), null));
    }
}
