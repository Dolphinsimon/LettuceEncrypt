// Copyright (c) Dolphinsimon.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Net.Security;
using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal;
using LettuceEncrypt.Internal.IO;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class TlsAlpnChallengeResponderTests
{
    private TlsAlpnChallengeResponder CreateResponder(
        ChallengeType challengeType = ChallengeType.Any,
        CertificateSelector selector = null,
        IClock clock = null)
    {
        var options = Options.Create(new LettuceEncryptOptions
        {
            AllowedChallengeTypes = challengeType
        });

        selector ??= new CertificateSelector(
            Options.Create(new LettuceEncryptOptions()),
            NullLogger<CertificateSelector>.Instance);

        clock ??= new TestClock();

        return new TlsAlpnChallengeResponder(
            options,
            selector,
            clock,
            NullLogger<TlsAlpnChallengeResponder>.Instance);
    }

    [Fact]
    public void IsEnabled_WithTlsAlpn01_ReturnsTrue()
    {
        var responder = CreateResponder(ChallengeType.TlsAlpn01);

        Assert.True(responder.IsEnabled);
    }

    [Fact]
    public void IsEnabled_WithAnyChallengeType_ReturnsTrue()
    {
        var responder = CreateResponder(ChallengeType.Any);

        Assert.True(responder.IsEnabled);
    }

    [Fact]
    public void IsEnabled_WithHttp01Only_ReturnsFalse()
    {
        var responder = CreateResponder(ChallengeType.Http01);

        Assert.False(responder.IsEnabled);
    }

    [Fact]
    public void IsEnabled_WithDns01Only_ReturnsFalse()
    {
        var responder = CreateResponder(ChallengeType.Dns01);

        Assert.False(responder.IsEnabled);
    }

    [Fact]
    public void OnSslAuthenticate_WithNoOpenChallenges_DoesNotAddProtocol()
    {
        var responder = CreateResponder();
        var context = Mock.Of<ConnectionContext>();
        var sslOptions = new SslServerAuthenticationOptions();

        responder.OnSslAuthenticate(context, sslOptions);

        Assert.Null(sslOptions.ApplicationProtocols);
    }

    [Fact]
    public void OnSslAuthenticate_WithOpenChallenge_AddsAcmeProtocol()
    {
        var selector = new CertificateSelector(
            Options.Create(new LettuceEncryptOptions()),
            NullLogger<CertificateSelector>.Instance);
        var responder = CreateResponder(selector: selector);

        // Prepare a challenge to increment the counter
        responder.PrepareChallengeCert("test.example.com", "key-authorization-string");

        var context = Mock.Of<ConnectionContext>();
        var sslOptions = new SslServerAuthenticationOptions();
        responder.OnSslAuthenticate(context, sslOptions);

        Assert.NotNull(sslOptions.ApplicationProtocols);
        Assert.Contains(sslOptions.ApplicationProtocols,
            p => p.Protocol.Span.SequenceEqual(System.Text.Encoding.UTF8.GetBytes("acme-tls/1")));
    }

    [Fact]
    public void PrepareChallengeCert_AddsChallengeCertToSelector()
    {
        var selector = new CertificateSelector(
            Options.Create(new LettuceEncryptOptions()),
            NullLogger<CertificateSelector>.Instance);
        var responder = CreateResponder(selector: selector);

        responder.PrepareChallengeCert("test.example.com", "key-authorization-string");

        // The selector should now have a challenge cert for this domain
        var cert = selector.Select(Mock.Of<ConnectionContext>(), "test.example.com");
        Assert.NotNull(cert);
    }

    [Fact]
    public void DiscardChallenge_RemovesChallengeCertFromSelector()
    {
        var selector = new CertificateSelector(
            Options.Create(new LettuceEncryptOptions()),
            NullLogger<CertificateSelector>.Instance);
        var responder = CreateResponder(selector: selector);

        responder.PrepareChallengeCert("test.example.com", "key-authorization-string");
        responder.DiscardChallenge("test.example.com");

        // After discard, selector should return null (no fallback configured)
        var cert = selector.Select(Mock.Of<ConnectionContext>(), "test.example.com");
        Assert.Null(cert);
    }

    [Fact]
    public void DiscardChallenge_DecrementsOpenChallenges()
    {
        var selector = new CertificateSelector(
            Options.Create(new LettuceEncryptOptions()),
            NullLogger<CertificateSelector>.Instance);
        var responder = CreateResponder(selector: selector);

        responder.PrepareChallengeCert("test.example.com", "key-authorization-string");
        responder.DiscardChallenge("test.example.com");

        // After discarding, OnSslAuthenticate should no longer add protocol
        var context = Mock.Of<ConnectionContext>();
        var sslOptions = new SslServerAuthenticationOptions();
        responder.OnSslAuthenticate(context, sslOptions);

        Assert.Null(sslOptions.ApplicationProtocols);
    }

    [Fact]
    public void Constructor_ThrowsOnNullOptions()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new TlsAlpnChallengeResponder(
                null,
                new CertificateSelector(Options.Create(new LettuceEncryptOptions()), NullLogger<CertificateSelector>.Instance),
                new TestClock(),
                NullLogger<TlsAlpnChallengeResponder>.Instance));
    }

    [Fact]
    public void Constructor_ThrowsOnNullCertificateSelector()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new TlsAlpnChallengeResponder(
                Options.Create(new LettuceEncryptOptions()),
                null,
                new TestClock(),
                NullLogger<TlsAlpnChallengeResponder>.Instance));
    }

    [Fact]
    public void Constructor_ThrowsOnNullClock()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new TlsAlpnChallengeResponder(
                Options.Create(new LettuceEncryptOptions()),
                new CertificateSelector(Options.Create(new LettuceEncryptOptions()), NullLogger<CertificateSelector>.Instance),
                null,
                NullLogger<TlsAlpnChallengeResponder>.Instance));
    }

    [Fact]
    public void Constructor_ThrowsOnNullLogger()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new TlsAlpnChallengeResponder(
                Options.Create(new LettuceEncryptOptions()),
                new CertificateSelector(Options.Create(new LettuceEncryptOptions()), NullLogger<CertificateSelector>.Instance),
                new TestClock(),
                null));
    }

    private class TestClock : IClock
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
    }
}
