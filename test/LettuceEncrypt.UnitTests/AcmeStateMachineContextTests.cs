// Copyright (c) Dolphinsimon.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal.AcmeStates;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class AcmeStateMachineContextTests
{
    [Fact]
    public void Constructor_SetsServicesProperty()
    {
        var services = Mock.Of<IServiceProvider>();
        var context = new AcmeStateMachineContext(services);

        Assert.Same(services, context.Services);
    }
}
