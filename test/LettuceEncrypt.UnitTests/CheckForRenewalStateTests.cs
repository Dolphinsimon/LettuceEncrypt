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

public class CheckForRenewalStateTests
{
    private class TestClock : IClock
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
    }

    private static IServiceProvider BuildServiceProvider(
        IOptions<LettuceEncryptOptions> options,
        CertificateSelector selector,
        TestClock clock)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(options);
        services.AddSingleton(selector);
        services.AddSingleton<IClock>(clock);
        services.AddSingleton(TerminalState.Singleton);
        services.AddScoped<AcmeStateMachineContext>();
        services.AddTransient<CheckForRenewalState>();
        services.AddTransient<BeginCertificateCreationState>();

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

        return services.BuildServiceProvider();
    }

    private (CheckForRenewalState state, CertificateSelector selector, TestClock clock) CreateState(
        LettuceEncryptOptions opts = null)
    {
        opts ??= new LettuceEncryptOptions
        {
            DomainNames = new[] { "test.example.com" },
            RenewalCheckPeriod = TimeSpan.FromMilliseconds(50),
            RenewDaysInAdvance = TimeSpan.FromDays(30)
        };

        var options = Options.Create(opts);
        var clock = new TestClock();
        var selector = new CertificateSelector(
            options,
            NullLogger<CertificateSelector>.Instance);

        var sp = BuildServiceProvider(options, selector, clock);
        var context = new AcmeStateMachineContext(sp);

        var state = new CheckForRenewalState(
            context,
            NullLogger<CheckForRenewalState>.Instance,
            options,
            selector,
            clock);

        return (state, selector, clock);
    }

    [Fact]
    public async Task MoveNext_WhenRenewalNotConfigured_TransitionsToTerminal()
    {
        var opts = new LettuceEncryptOptions
        {
            DomainNames = new[] { "test.example.com" },
            RenewalCheckPeriod = null,
            RenewDaysInAdvance = null
        };
        var (state, _, _) = CreateState(opts);

        var nextState = await state.MoveNextAsync(CancellationToken.None);

        Assert.IsType<TerminalState>(nextState);
    }

    [Fact]
    public async Task MoveNext_WhenRenewDaysInAdvanceIsNull_TransitionsToTerminal()
    {
        var opts = new LettuceEncryptOptions
        {
            DomainNames = new[] { "test.example.com" },
            RenewalCheckPeriod = TimeSpan.FromDays(1),
            RenewDaysInAdvance = null
        };
        var (state, _, _) = CreateState(opts);

        var nextState = await state.MoveNextAsync(CancellationToken.None);

        Assert.IsType<TerminalState>(nextState);
    }

    [Fact]
    public async Task MoveNext_WhenNoCertForDomain_TransitionsToBeginCertificateCreation()
    {
        var (state, _, _) = CreateState();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var nextState = await state.MoveNextAsync(cts.Token);

        Assert.IsType<BeginCertificateCreationState>(nextState);
    }

    [Fact]
    public async Task MoveNext_WhenCertExpiringSoon_TransitionsToBeginCertificateCreation()
    {
        var (state, selector, clock) = CreateState();

        // Add a cert that expires in 10 days (less than 30 days renewal threshold)
        var cert = CreateTestCert("test.example.com", DateTimeOffset.UtcNow.AddDays(10));
        selector.Add(cert);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var nextState = await state.MoveNextAsync(cts.Token);

        Assert.IsType<BeginCertificateCreationState>(nextState);
    }

    [Fact]
    public async Task MoveNext_WhenCancelled_ThrowsOrTransitionsToTerminal()
    {
        var (state, selector, _) = CreateState();

        // Add a cert that won't expire for a long time
        var cert = CreateTestCert("test.example.com", DateTimeOffset.UtcNow.AddDays(365));
        selector.Add(cert);

        using var cts = new CancellationTokenSource();
        // Cancel immediately after a short delay
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        // The state may throw TaskCanceledException from Task.Delay or return TerminalState
        // depending on timing
        try
        {
            var nextState = await state.MoveNextAsync(cts.Token);
            Assert.IsType<TerminalState>(nextState);
        }
        catch (OperationCanceledException)
        {
            // Expected when Task.Delay is cancelled
        }
    }
}
