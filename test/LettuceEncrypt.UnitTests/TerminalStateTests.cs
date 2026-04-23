// Copyright (c) Dolphinsimon.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal.AcmeStates;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class TerminalStateTests
{
    [Fact]
    public void Singleton_ReturnsSameInstance()
    {
        var first = TerminalState.Singleton;
        var second = TerminalState.Singleton;

        Assert.Same(first, second);
    }

    [Fact]
    public async Task MoveNextAsync_ThrowsOperationCanceledException()
    {
        var state = TerminalState.Singleton;

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => state.MoveNextAsync(CancellationToken.None));
    }

    [Fact]
    public async Task MoveNextAsync_WithCancelledToken_ThrowsOperationCanceledException()
    {
        var state = TerminalState.Singleton;
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => state.MoveNextAsync(cts.Token));
    }
}
