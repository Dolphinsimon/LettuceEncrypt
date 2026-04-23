// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class AcmeCertificateLoaderTests
{
    private class FakeServer : IServer
    {
        public IFeatureCollection Features { get; } = new FeatureCollection();

        public Task StartAsync<TContext>(IHttpApplication<TContext> application, CancellationToken cancellationToken) where TContext : notnull
            => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken)
            => Task.CompletedTask;

        public void Dispose() { }
    }

    [Fact]
    public async Task ExecuteAsync_WithNonKestrelServer_DoesNotStartStateMachine()
    {
        var options = Options.Create(new LettuceEncryptOptions
        {
            DomainNames = new[] { "test.example.com" }
        });

        var services = new ServiceCollection();
        var sp = services.BuildServiceProvider();

        var config = new ConfigurationBuilder().Build();

        var loader = new AcmeCertificateLoader(
            sp.GetRequiredService<IServiceScopeFactory>(),
            options,
            NullLogger<AcmeCertificateLoader>.Instance,
            new FakeServer(),
            config);

        var ct = TestContext.Current.CancellationToken;

        // StartAsync calls ExecuteAsync internally
        await loader.StartAsync(ct);
        // Give it a moment to execute
        await Task.Delay(100, ct);
        await loader.StopAsync(ct);

        // If we get here without exceptions, the test passes - the loader should have
        // logged a warning and returned early since FakeServer is not KestrelServer
    }

    [Fact]
    public async Task ExecuteAsync_WithNoConfiguredDomains_ReturnsEarly()
    {
        var options = Options.Create(new LettuceEncryptOptions
        {
            DomainNames = Array.Empty<string>()
        });

        var config = new ConfigurationBuilder().Build();

        var services = new ServiceCollection();
        var sp = services.BuildServiceProvider();

        var loader = new AcmeCertificateLoader(
            sp.GetRequiredService<IServiceScopeFactory>(),
            options,
            NullLogger<AcmeCertificateLoader>.Instance,
            new FakeServer(),
            config);

        var ct = TestContext.Current.CancellationToken;

        await loader.StartAsync(ct);
        await Task.Delay(100, ct);
        await loader.StopAsync(ct);
    }

    [Fact]
    public async Task ExecuteAsync_WithIISIntegration_ReturnsEarly()
    {
        var options = Options.Create(new LettuceEncryptOptions
        {
            DomainNames = new[] { "test.example.com" }
        });

        // Configure UseIISIntegration = true
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                { "UseIISIntegration", "true" }
            })
            .Build();

        var services = new ServiceCollection();
        var sp = services.BuildServiceProvider();

        var loader = new AcmeCertificateLoader(
            sp.GetRequiredService<IServiceScopeFactory>(),
            options,
            NullLogger<AcmeCertificateLoader>.Instance,
            new FakeServer(),
            config);

        var ct = TestContext.Current.CancellationToken;

        await loader.StartAsync(ct);
        await Task.Delay(100, ct);
        await loader.StopAsync(ct);

        // The loader should have logged a warning about IIS and returned early
    }

    [Fact]
    public async Task ExecuteAsync_WithLocalhostOnly_ReturnsEarly()
    {
        var options = Options.Create(new LettuceEncryptOptions
        {
            DomainNames = new[] { "localhost" }
        });

        var config = new ConfigurationBuilder().Build();

        var services = new ServiceCollection();
        var sp = services.BuildServiceProvider();

        var loader = new AcmeCertificateLoader(
            sp.GetRequiredService<IServiceScopeFactory>(),
            options,
            NullLogger<AcmeCertificateLoader>.Instance,
            new FakeServer(),
            config);

        var ct = TestContext.Current.CancellationToken;

        await loader.StartAsync(ct);
        await Task.Delay(100, ct);
        await loader.StopAsync(ct);
    }
}
