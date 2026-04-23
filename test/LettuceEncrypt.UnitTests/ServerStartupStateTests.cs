// Copyright (c) Nate McMaster.
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

using static TestUtils;

public class ServerStartupStateTests
{
    private class TestClock : IClock
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
    }

    private (ServerStartupState state, CertificateSelector selector) CreateState(string[] domainNames)
    {
        var options = Options.Create(new LettuceEncryptOptions
        {
            DomainNames = domainNames,
            RenewalCheckPeriod = TimeSpan.FromMilliseconds(50),
            RenewDaysInAdvance = TimeSpan.FromDays(30)
        });

        var selector = new CertificateSelector(
            options,
            NullLogger<CertificateSelector>.Instance);

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
        services.AddTransient<ServerStartupState>();

        // Dependencies for BeginCertificateCreationState -> AcmeCertificateFactory
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
        services.AddSingleton<IConsole>(PhysicalConsole.Singleton);
        services.AddSingleton<IEnumerable<ICertificateRepository>>(
            Array.Empty<ICertificateRepository>());

        var sp = services.BuildServiceProvider();
        var context = new AcmeStateMachineContext(sp);

        var state = new ServerStartupState(
            context,
            options,
            selector,
            NullLogger<ServerStartupState>.Instance);

        return (state, selector);
    }

    [Fact]
    public async Task MoveNext_WithCertsForAllDomains_TransitionsToCheckForRenewal()
    {
        var domains = new[] { "test.example.com" };
        var (state, selector) = CreateState(domains);

        // Add a certificate for the domain
        var cert = CreateTestCert("test.example.com");
        selector.Add(cert);

        var nextState = await state.MoveNextAsync(CancellationToken.None);

        Assert.IsType<CheckForRenewalState>(nextState);
    }

    [Fact]
    public async Task MoveNext_WithNoCerts_TransitionsToBeginCertificateCreation()
    {
        var domains = new[] { "test.example.com" };
        var (state, selector) = CreateState(domains);

        // Don't add any certificates
        var nextState = await state.MoveNextAsync(CancellationToken.None);

        Assert.IsType<BeginCertificateCreationState>(nextState);
    }

    [Fact]
    public async Task MoveNext_WithCancelledToken_ThrowsOperationCanceledException()
    {
        var domains = new[] { "test.example.com" };
        var (state, _) = CreateState(domains);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => state.MoveNextAsync(cts.Token));
    }
}
