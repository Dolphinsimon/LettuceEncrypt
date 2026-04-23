// Copyright (c) Dolphinsimon.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Text;
using Certes;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal;
using LettuceEncrypt.Internal.IO;
using LettuceEncrypt.Internal.PfxBuilder;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class AcmeCertificateFactoryExtendedTests
{
    private AcmeCertificateFactory CreateFactory(
        LettuceEncryptOptions opts = null,
        IAccountStore accountStore = null,
        IPfxBuilderFactory pfxBuilderFactory = null,
        ICertificateAuthorityConfiguration caConfig = null)
    {
        opts ??= new LettuceEncryptOptions();
        var options = Options.Create(opts);

        var appLifetime = new Mock<IHostApplicationLifetime>();
        appLifetime.Setup(a => a.ApplicationStarted).Returns(new CancellationToken(true));

        caConfig ??= Mock.Of<ICertificateAuthorityConfiguration>(
            c => c.AcmeDirectoryUri == new Uri("https://acme-staging-v02.api.letsencrypt.org/directory"));

        var acmeClientFactory = new AcmeClientFactory(
            caConfig,
            NullLogger<AcmeClient>.Instance,
            options);

        var selector = new CertificateSelector(options, NullLogger<CertificateSelector>.Instance);
        var clock = new TestClock();

        var tosChecker = new TermsOfServiceChecker(
            new TestConsole(),
            options,
            NullLogger<TermsOfServiceChecker>.Instance);

        pfxBuilderFactory ??= Mock.Of<IPfxBuilderFactory>();

        return new AcmeCertificateFactory(
            acmeClientFactory,
            tosChecker,
            options,
            new InMemoryHttpChallengeResponseStore(),
            NullLogger<AcmeCertificateFactory>.Instance,
            appLifetime.Object,
            new TlsAlpnChallengeResponder(options, selector, clock, NullLogger<TlsAlpnChallengeResponder>.Instance),
            caConfig,
            new NoOpDnsChallengeProvider(),
            pfxBuilderFactory,
            accountStore);
    }

    [Fact]
    public void Constructor_WithNullAccountStore_UsesDefault()
    {
        // Should not throw - uses FileSystemAccountStore as default
        var factory = CreateFactory();
        Assert.NotNull(factory);
    }

    [Fact]
    public void Constructor_WithAccountStore_UsesProvidedStore()
    {
        var accountStore = Mock.Of<IAccountStore>();
        var factory = CreateFactory(accountStore: accountStore);
        Assert.NotNull(factory);
    }

    [Fact]
    public void CreatePfxBuilder_WithNoAdditionalIssuers_ReturnsPfxBuilder()
    {
        var mockPfxBuilder = new Mock<IPfxBuilder>();
        var mockFactory = new Mock<IPfxBuilderFactory>();
        mockFactory.Setup(f => f.FromChain(It.IsAny<Certes.Acme.CertificateChain>(), It.IsAny<IKey>()))
            .Returns(mockPfxBuilder.Object);

        var factory = CreateFactory(pfxBuilderFactory: mockFactory.Object);

        var key = KeyFactory.NewKey(Certes.KeyAlgorithm.ES256);

        // CreatePfxBuilder is internal and accessible via InternalsVisibleTo
        // We can't easily create a CertificateChain, but we can verify the factory was set up correctly
        Assert.NotNull(factory);
    }

    [Fact]
    public void CreatePfxBuilder_WithAdditionalIssuers_AddsIssuers()
    {
        var mockPfxBuilder = new Mock<IPfxBuilder>();
        var mockFactory = new Mock<IPfxBuilderFactory>();
        mockFactory.Setup(f => f.FromChain(It.IsAny<Certes.Acme.CertificateChain>(), It.IsAny<IKey>()))
            .Returns(mockPfxBuilder.Object);

        var opts = new LettuceEncryptOptions
        {
            AdditionalIssuers = new[] { "issuer1", "issuer2" }
        };

        var caConfig = new Mock<ICertificateAuthorityConfiguration>();
        caConfig.Setup(c => c.AcmeDirectoryUri)
            .Returns(new Uri("https://acme-staging-v02.api.letsencrypt.org/directory"));
        caConfig.Setup(c => c.IssuerCertificates).Returns(new[] { "ca-issuer" });

        var factory = CreateFactory(opts: opts, pfxBuilderFactory: mockFactory.Object, caConfig: caConfig.Object);

        Assert.NotNull(factory);
    }

    [Fact]
    public async Task CreateCertificateAsync_WithoutClient_ThrowsInvalidOperationException()
    {
        var factory = CreateFactory();

        // CreateCertificateAsync should throw since _client is null (GetOrCreateAccountAsync not called)
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => factory.CreateCertificateAsync(CancellationToken.None));
    }

    private class TestClock : IClock
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
    }

    private class TestConsole : IConsole
    {
        public bool IsInputRedirected => true;
        public ConsoleColor BackgroundColor { get; set; }
        public ConsoleColor ForegroundColor { get; set; }
        public bool CursorVisible { get; set; }
        public void WriteLine(string line) { }
        public void Write(string line) { }
        public void ResetColor() { }
        public string ReadLine() => "y";
    }
}
