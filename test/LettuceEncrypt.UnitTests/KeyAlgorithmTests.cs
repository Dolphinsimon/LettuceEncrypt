// Copyright (c) Dolphinsimon.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Xunit;

namespace LettuceEncrypt.UnitTests;

public class KeyAlgorithmTests
{
    [Fact]
    public void RS256_HasValue0()
    {
        Assert.Equal(0, (int)KeyAlgorithm.RS256);
    }

    [Fact]
    public void ES256_HasValue1()
    {
        Assert.Equal(1, (int)KeyAlgorithm.ES256);
    }

    [Fact]
    public void ES384_HasValue2()
    {
        Assert.Equal(2, (int)KeyAlgorithm.ES384);
    }

    [Fact]
    public void ES512_HasValue3()
    {
        Assert.Equal(3, (int)KeyAlgorithm.ES512);
    }

    [Fact]
    public void AllValuesAreDefined()
    {
        var values = Enum.GetValues<KeyAlgorithm>();
        Assert.Equal(4, values.Length);
    }
}
