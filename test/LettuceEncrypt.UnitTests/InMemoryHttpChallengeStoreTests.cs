// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class InMemoryHttpChallengeStoreTests
{
    [Fact]
    public void AddAndRetrieveChallenge()
    {
        var store = new InMemoryHttpChallengeResponseStore();
        store.AddChallengeResponse("token1", "response1");

        Assert.True(store.TryGetResponse("token1", out var value));
        Assert.Equal("response1", value);
    }

    [Fact]
    public void TryGetResponse_ReturnsFalseForMissingToken()
    {
        var store = new InMemoryHttpChallengeResponseStore();

        Assert.False(store.TryGetResponse("nonexistent", out var value));
        Assert.Null(value);
    }

    [Fact]
    public void AddChallengeResponse_OverwritesExistingToken()
    {
        var store = new InMemoryHttpChallengeResponseStore();
        store.AddChallengeResponse("token1", "response1");
        store.AddChallengeResponse("token1", "response2");

        Assert.True(store.TryGetResponse("token1", out var value));
        Assert.Equal("response2", value);
    }

    [Fact]
    public void MultipleTokensCanBeStored()
    {
        var store = new InMemoryHttpChallengeResponseStore();
        store.AddChallengeResponse("token1", "response1");
        store.AddChallengeResponse("token2", "response2");
        store.AddChallengeResponse("token3", "response3");

        Assert.True(store.TryGetResponse("token1", out var v1));
        Assert.Equal("response1", v1);
        Assert.True(store.TryGetResponse("token2", out var v2));
        Assert.Equal("response2", v2);
        Assert.True(store.TryGetResponse("token3", out var v3));
        Assert.Equal("response3", v3);
    }
}
