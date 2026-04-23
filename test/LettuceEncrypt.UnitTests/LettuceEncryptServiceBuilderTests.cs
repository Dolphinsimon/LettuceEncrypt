// Copyright (c) Dolphinsimon.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class LettuceEncryptServiceBuilderTests
{
    [Fact]
    public void Constructor_SetsServices()
    {
        var services = new ServiceCollection();
        var builder = new LettuceEncryptServiceBuilder(services);

        Assert.Same(services, builder.Services);
    }

    [Fact]
    public void Constructor_ThrowsOnNullServices()
    {
        Assert.Throws<ArgumentNullException>(() => new LettuceEncryptServiceBuilder(null));
    }
}
