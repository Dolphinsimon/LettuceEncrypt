// Copyright (c) Dolphinsimon.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class NoOpDnsChallengeProviderTests
{
    [Fact]
    public async Task AddTxtRecordAsync_ReturnsDnsTxtRecordContext()
    {
        var provider = new NoOpDnsChallengeProvider();
        var domainName = "example.com";
        var txt = "challenge-token";

        var result = await provider.AddTxtRecordAsync(domainName, txt, TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.Equal(domainName, result.DomainName);
        Assert.Equal(txt, result.Txt);
    }

    [Fact]
    public async Task RemoveTxtRecordAsync_CompletesSuccessfully()
    {
        var provider = new NoOpDnsChallengeProvider();
        var context = new DnsTxtRecordContext("example.com", "token");

        // Should complete without throwing
        await provider.RemoveTxtRecordAsync(context, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task AddTxtRecordAsync_WithCancellationToken()
    {
        var provider = new NoOpDnsChallengeProvider();
        using var cts = new CancellationTokenSource();

        var result = await provider.AddTxtRecordAsync("test.com", "value", cts.Token);

        Assert.NotNull(result);
        Assert.Equal("test.com", result.DomainName);
    }

    [Fact]
    public async Task RemoveTxtRecordAsync_WithCancellationToken()
    {
        var provider = new NoOpDnsChallengeProvider();
        var context = new DnsTxtRecordContext("test.com", "value");
        using var cts = new CancellationTokenSource();

        await provider.RemoveTxtRecordAsync(context, cts.Token);
    }
}
