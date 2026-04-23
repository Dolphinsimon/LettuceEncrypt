// Copyright (c) Dolphinsimon.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Acme;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class DnsTxtRecordContextTests
{
    [Fact]
    public void Constructor_SetsProperties()
    {
        var domainName = "example.com";
        var txt = "some-txt-value";

        var context = new DnsTxtRecordContext(domainName, txt);

        Assert.Equal(domainName, context.DomainName);
        Assert.Equal(txt, context.Txt);
    }

    [Fact]
    public void Constructor_WithEmptyStrings()
    {
        var context = new DnsTxtRecordContext(string.Empty, string.Empty);

        Assert.Equal(string.Empty, context.DomainName);
        Assert.Equal(string.Empty, context.Txt);
    }

    [Fact]
    public void Constructor_WithWildcardDomain()
    {
        var context = new DnsTxtRecordContext("*.example.com", "acme-challenge-token");

        Assert.Equal("*.example.com", context.DomainName);
        Assert.Equal("acme-challenge-token", context.Txt);
    }
}
