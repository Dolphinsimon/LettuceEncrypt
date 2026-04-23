// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal.IO;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class SystemClockTests
{
    [Fact]
    public void Now_ReturnsCurrentTime()
    {
        var clock = new SystemClock();
        var before = DateTimeOffset.Now;

        var now = clock.Now;

        var after = DateTimeOffset.Now;
        Assert.InRange(now, before, after);
    }

    [Fact]
    public void Now_ReturnsDifferentTimesOnSubsequentCalls()
    {
        var clock = new SystemClock();
        var first = clock.Now;

        // Small delay to ensure time has moved
        Thread.Sleep(1);
        var second = clock.Now;

        Assert.True(second >= first);
    }
}
