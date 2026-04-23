// Copyright (c) Dolphinsimon.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes;
using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class AcmeClientFactoryTests
{
    [Fact]
    public void Create_ReturnsAcmeClient()
    {
        var caConfig = Mock.Of<ICertificateAuthorityConfiguration>(
            c => c.AcmeDirectoryUri == new Uri("https://acme-staging-v02.api.letsencrypt.org/directory"));
        var options = Options.Create(new LettuceEncryptOptions());

        var factory = new AcmeClientFactory(
            caConfig,
            NullLogger<AcmeClient>.Instance,
            options);

        var key = KeyFactory.NewKey(Certes.KeyAlgorithm.ES256);
        var client = factory.Create(key);

        Assert.NotNull(client);
    }

    [Fact]
    public void Create_UsesDirectoryUriFromConfiguration()
    {
        var expectedUri = new Uri("https://custom-acme.example.com/directory");
        var caConfig = Mock.Of<ICertificateAuthorityConfiguration>(
            c => c.AcmeDirectoryUri == expectedUri);
        var options = Options.Create(new LettuceEncryptOptions());

        var factory = new AcmeClientFactory(
            caConfig,
            NullLogger<AcmeClient>.Instance,
            options);

        var key = KeyFactory.NewKey(Certes.KeyAlgorithm.ES256);
        var client = factory.Create(key);

        Assert.NotNull(client);
    }
}
