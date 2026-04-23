// Copyright (c) Dolphinsimon.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt;
using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal;
using LettuceEncrypt.Internal.PfxBuilder;
using McMaster.AspNetCore.Kestrel.Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class LettuceEncryptServiceCollectionExtensionsTests
{
    [Fact]
    public void AddLettuceEncrypt_RegistersExpectedServiceDescriptors()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddLettuceEncrypt();

        // Verify service descriptors are registered (without resolving which needs IServer etc.)
        Assert.Contains(services, sd => sd.ServiceType == typeof(CertificateSelector));
        Assert.Contains(services, sd => sd.ServiceType == typeof(IServerCertificateSelector));
        Assert.Contains(services, sd => sd.ServiceType == typeof(ICertificateAuthorityConfiguration));
        Assert.Contains(services, sd => sd.ServiceType == typeof(IHttpChallengeResponseStore));
        Assert.Contains(services, sd => sd.ServiceType == typeof(IDnsChallengeProvider));
        Assert.Contains(services, sd => sd.ServiceType == typeof(IPfxBuilderFactory));
        Assert.Contains(services, sd => sd.ServiceType == typeof(TlsAlpnChallengeResponder));
        Assert.Contains(services, sd => sd.ServiceType == typeof(HttpChallengeResponseMiddleware));
    }

    [Fact]
    public void AddLettuceEncrypt_WithConfigure_SetsOptions()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddLettuceEncrypt(options =>
        {
            options.DomainNames = new[] { "test.example.com" };
            options.EmailAddress = "test@example.com";
            options.AcceptTermsOfService = true;
        });

        var sp = services.BuildServiceProvider();
        var options = sp.GetRequiredService<IOptions<LettuceEncryptOptions>>();

        Assert.Equal(new[] { "test.example.com" }, options.Value.DomainNames);
        Assert.Equal("test@example.com", options.Value.EmailAddress);
        Assert.True(options.Value.AcceptTermsOfService);
    }

    [Fact]
    public void AddLettuceEncrypt_ReturnsServiceBuilder()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        var builder = services.AddLettuceEncrypt();

        Assert.NotNull(builder);
        Assert.IsAssignableFrom<ILettuceEncryptServiceBuilder>(builder);
    }

    [Fact]
    public void AddLettuceEncrypt_RegistersAcmeStateServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddLettuceEncrypt();

        // Verify state machine services are registered
        Assert.Contains(services, sd => sd.ServiceType == typeof(LettuceEncrypt.Internal.AcmeStates.ServerStartupState));
        Assert.Contains(services, sd => sd.ServiceType == typeof(LettuceEncrypt.Internal.AcmeStates.CheckForRenewalState));
        Assert.Contains(services, sd => sd.ServiceType == typeof(LettuceEncrypt.Internal.AcmeStates.BeginCertificateCreationState));
        Assert.Contains(services, sd => sd.ServiceType == typeof(LettuceEncrypt.Internal.AcmeStates.AcmeStateMachineContext));
    }

    [Fact]
    public void AddLettuceEncrypt_WithNoArgs_RegistersServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        var builder = services.AddLettuceEncrypt();

        Assert.NotNull(builder);
        Assert.Contains(services, sd => sd.ServiceType == typeof(CertificateSelector));
    }
}
