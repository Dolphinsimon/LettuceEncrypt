// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class LoggerExtensionsTests
{
    [Fact]
    public void LogAcmeAction_WhenTraceEnabled_LogsMessage()
    {
        var logger = new Mock<ILogger>();
        logger.Setup(l => l.IsEnabled(LogLevel.Trace)).Returns(true);

        logger.Object.LogAcmeAction("TestAction");

        logger.Verify(
            l => l.Log(
                LogLevel.Trace,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("TestAction")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);
    }

    [Fact]
    public void LogAcmeAction_WhenTraceDisabled_DoesNotLog()
    {
        var logger = new Mock<ILogger>();
        logger.Setup(l => l.IsEnabled(LogLevel.Trace)).Returns(false);

        logger.Object.LogAcmeAction("TestAction");

        logger.Verify(
            l => l.Log(
                It.IsAny<LogLevel>(),
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Never);
    }

    [Fact]
    public void LogAcmeAction_WithNullLogger_UsesNullLogger()
    {
        // Should not throw even with NullLogger
        ILogger logger = NullLogger.Instance;
        logger.LogAcmeAction("TestAction");
    }

    [Fact]
    public void LogAcmeAction_WithResourceContext_WhenTraceEnabled_LogsMessage()
    {
        var logger = new Mock<ILogger>();
        logger.Setup(l => l.IsEnabled(LogLevel.Trace)).Returns(true);

        var resourceContext = new Mock<Certes.Acme.IResourceContext<Certes.Acme.Resource.Account>>();
        resourceContext.Setup(r => r.Location).Returns(new Uri("https://acme.example.com/acct/123"));

        logger.Object.LogAcmeAction("FetchAccount", resourceContext.Object);

        logger.Verify(
            l => l.Log(
                LogLevel.Trace,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("FetchAccount")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);
    }

    [Fact]
    public void LogAcmeAction_WithResourceContext_WhenTraceDisabled_DoesNotLog()
    {
        var logger = new Mock<ILogger>();
        logger.Setup(l => l.IsEnabled(LogLevel.Trace)).Returns(false);

        var resourceContext = new Mock<Certes.Acme.IResourceContext<Certes.Acme.Resource.Account>>();
        resourceContext.Setup(r => r.Location).Returns(new Uri("https://acme.example.com/acct/123"));

        logger.Object.LogAcmeAction("FetchAccount", resourceContext.Object);

        logger.Verify(
            l => l.Log(
                It.IsAny<LogLevel>(),
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Never);
    }
}
