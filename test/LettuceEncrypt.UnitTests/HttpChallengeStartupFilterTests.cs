// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class HttpChallengeStartupFilterTests
{
    [Fact]
    public void Configure_ReturnsActionThatCallsNext()
    {
        var filter = new HttpChallengeStartupFilter();
        var nextCalled = false;
        Action<IApplicationBuilder> next = _ => nextCalled = true;

        var configuredAction = filter.Configure(next);

        Assert.NotNull(configuredAction);

        var appBuilder = new Mock<IApplicationBuilder>();
        appBuilder.Setup(a => a.New()).Returns(appBuilder.Object);
        appBuilder.Setup(a => a.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()))
            .Returns(appBuilder.Object);
        appBuilder.Setup(a => a.Build()).Returns(Mock.Of<RequestDelegate>());

        configuredAction(appBuilder.Object);

        Assert.True(nextCalled);
    }
}
