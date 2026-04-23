// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal;
using LettuceEncrypt.Internal.IO;
using McMaster.AspNetCore.Kestrel.Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class LettuceEncryptKestrelHttpsOptionsExtensionsTests
{
    [Fact]
    public void UseLettuceEncrypt_WithServiceProvider_ThrowsWhenSelectorMissing()
    {
        var services = new ServiceCollection().BuildServiceProvider();
        var httpsOptions = new HttpsConnectionAdapterOptions();

        Assert.Throws<InvalidOperationException>(() =>
            httpsOptions.UseLettuceEncrypt(services));
    }

    [Fact]
    public void UseLettuceEncrypt_WithServiceProvider_ThrowsWhenResponderMissing()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IServerCertificateSelector>());
        var sp = services.BuildServiceProvider();
        var httpsOptions = new HttpsConnectionAdapterOptions();

        Assert.Throws<InvalidOperationException>(() =>
            httpsOptions.UseLettuceEncrypt(sp));
    }

    [Fact]
    public void UseLettuceEncrypt_WithServiceProvider_ConfiguresOptions()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IServerCertificateSelector>());
        services.AddSingleton(new TlsAlpnChallengeResponder(
            Options.Create(new LettuceEncryptOptions()),
            new CertificateSelector(
                Options.Create(new LettuceEncryptOptions()),
                NullLogger<CertificateSelector>.Instance),
            new TestClock(),
            NullLogger<TlsAlpnChallengeResponder>.Instance));
        var sp = services.BuildServiceProvider();

        var httpsOptions = new HttpsConnectionAdapterOptions();
        var result = httpsOptions.UseLettuceEncrypt(sp);

        Assert.Same(httpsOptions, result);
        Assert.NotNull(httpsOptions.OnAuthenticate);
        Assert.NotNull(httpsOptions.ServerCertificateSelector);
    }

    [Fact]
    public void UseLettuceEncrypt_Internal_ChainsExistingOnAuthenticate()
    {
        var selector = Mock.Of<IServerCertificateSelector>();
        var responder = new TlsAlpnChallengeResponder(
            Options.Create(new LettuceEncryptOptions()),
            new CertificateSelector(
                Options.Create(new LettuceEncryptOptions()),
                NullLogger<CertificateSelector>.Instance),
            new TestClock(),
            NullLogger<TlsAlpnChallengeResponder>.Instance);

        var existingHandlerCalled = false;
        var httpsOptions = new HttpsConnectionAdapterOptions();
        httpsOptions.OnAuthenticate = (ctx, opts) => existingHandlerCalled = true;

        httpsOptions.UseLettuceEncrypt(selector, responder);

        // Invoke the new handler - it should chain to existing
        httpsOptions.OnAuthenticate(
            Mock.Of<ConnectionContext>(),
            new System.Net.Security.SslServerAuthenticationOptions());

        Assert.True(existingHandlerCalled);
    }

    [Fact]
    public void UseLettuceEncrypt_Internal_WorksWithNullExistingHandler()
    {
        var selector = Mock.Of<IServerCertificateSelector>();
        var responder = new TlsAlpnChallengeResponder(
            Options.Create(new LettuceEncryptOptions()),
            new CertificateSelector(
                Options.Create(new LettuceEncryptOptions()),
                NullLogger<CertificateSelector>.Instance),
            new TestClock(),
            NullLogger<TlsAlpnChallengeResponder>.Instance);

        var httpsOptions = new HttpsConnectionAdapterOptions();
        httpsOptions.OnAuthenticate = null;

        httpsOptions.UseLettuceEncrypt(selector, responder);

        // Should not throw when invoked
        httpsOptions.OnAuthenticate(
            Mock.Of<ConnectionContext>(),
            new System.Net.Security.SslServerAuthenticationOptions());
    }

    private class TestClock : IClock
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
    }
}
