// Copyright (c) Dolphinsimon.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal;
using LettuceEncrypt.Internal.AcmeStates;
using LettuceEncrypt.Internal.IO;
using LettuceEncrypt.Internal.PfxBuilder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class BeginCertificateCreationStateTests
{
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

    [Fact]
    public async Task MoveNextAsync_WhenFactoryThrows_PropagatesException()
    {
        var options = Options.Create(new LettuceEncryptOptions
        {
            DomainNames = new[] { "test.example.com" }
        });

        var selector = new CertificateSelector(options, NullLogger<CertificateSelector>.Instance);
        var clock = new TestClock();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(options);
        services.AddSingleton(selector);
        services.AddSingleton<IClock>(clock);
        services.AddSingleton(TerminalState.Singleton);
        services.AddScoped<AcmeStateMachineContext>();
        services.AddTransient<CheckForRenewalState>();
        services.AddTransient<BeginCertificateCreationState>();

        var appLifetime = new Mock<IHostApplicationLifetime>();
        appLifetime.Setup(a => a.ApplicationStarted).Returns(new CancellationToken(true));
        services.AddSingleton(appLifetime.Object);

        services.AddSingleton<AcmeClientFactory>();
        services.AddSingleton<TermsOfServiceChecker>();
        services.AddSingleton<IHttpChallengeResponseStore, InMemoryHttpChallengeResponseStore>();
        services.AddSingleton(Mock.Of<ICertificateAuthorityConfiguration>(
            c => c.AcmeDirectoryUri == new Uri("https://acme-staging-v02.api.letsencrypt.org/directory")));
        services.AddSingleton<IDnsChallengeProvider, NoOpDnsChallengeProvider>();
        services.AddSingleton(Mock.Of<IPfxBuilderFactory>());
        services.AddSingleton<TlsAlpnChallengeResponder>();
        services.AddSingleton<AcmeCertificateFactory>();
        services.AddSingleton<IConsole>(new TestConsole());
        services.AddSingleton<IEnumerable<ICertificateRepository>>(Array.Empty<ICertificateRepository>());

        var sp = services.BuildServiceProvider();
        var context = new AcmeStateMachineContext(sp);

        var state = new BeginCertificateCreationState(
            context,
            NullLogger<ServerStartupState>.Instance,
            options,
            sp.GetRequiredService<AcmeCertificateFactory>(),
            selector,
            Array.Empty<ICertificateRepository>());

        // The factory hasn't been initialized with an account, so it should throw
        // The inner exception is wrapped in a generic Exception by the state
        var ex = await Assert.ThrowsAnyAsync<Exception>(
            () => state.MoveNextAsync(CancellationToken.None));
        Assert.NotNull(ex);
    }

    [Fact]
    public async Task MoveNextAsync_WithCancelled_ThrowsOperationCanceledException()
    {
        var options = Options.Create(new LettuceEncryptOptions
        {
            DomainNames = new[] { "test.example.com" }
        });

        var selector = new CertificateSelector(options, NullLogger<CertificateSelector>.Instance);
        var clock = new TestClock();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(options);
        services.AddSingleton(selector);
        services.AddSingleton<IClock>(clock);
        services.AddSingleton(TerminalState.Singleton);
        services.AddScoped<AcmeStateMachineContext>();
        services.AddTransient<CheckForRenewalState>();

        var appLifetime = new Mock<IHostApplicationLifetime>();
        appLifetime.Setup(a => a.ApplicationStarted).Returns(new CancellationToken(true));
        services.AddSingleton(appLifetime.Object);
        services.AddSingleton(Mock.Of<ICertificateAuthorityConfiguration>(
            c => c.AcmeDirectoryUri == new Uri("https://acme-staging-v02.api.letsencrypt.org/directory")));
        services.AddSingleton<IConsole>(new TestConsole());

        var mockFactory = new Mock<AcmeCertificateFactory>(
            MockBehavior.Strict,
            new AcmeClientFactory(
                Mock.Of<ICertificateAuthorityConfiguration>(
                    c => c.AcmeDirectoryUri == new Uri("https://acme-staging-v02.api.letsencrypt.org/directory")),
                NullLogger<AcmeClient>.Instance,
                options),
            new TermsOfServiceChecker(new TestConsole(), options, NullLogger<TermsOfServiceChecker>.Instance),
            options,
            new InMemoryHttpChallengeResponseStore(),
            NullLogger<AcmeCertificateFactory>.Instance,
            appLifetime.Object,
            new TlsAlpnChallengeResponder(options, selector, clock, NullLogger<TlsAlpnChallengeResponder>.Instance),
            Mock.Of<ICertificateAuthorityConfiguration>(
                c => c.AcmeDirectoryUri == new Uri("https://acme-staging-v02.api.letsencrypt.org/directory")),
            new NoOpDnsChallengeProvider(),
            Mock.Of<IPfxBuilderFactory>(),
            null);

        var sp = services.BuildServiceProvider();
        var context = new AcmeStateMachineContext(sp);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var state = new BeginCertificateCreationState(
            context,
            NullLogger<ServerStartupState>.Instance,
            options,
            mockFactory.Object,
            selector,
            Array.Empty<ICertificateRepository>());

        // Should throw because the token is already cancelled
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => state.MoveNextAsync(cts.Token));
    }
}
