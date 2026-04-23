// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Acme;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class EabCredentialsTests
{
    [Fact]
    public void DefaultValues_AreNull()
    {
        var creds = new EabCredentials();

        Assert.Null(creds.EabKeyId);
        Assert.Null(creds.EabKey);
        Assert.Null(creds.EabKeyAlg);
    }

    [Fact]
    public void Properties_CanBeSet()
    {
        var creds = new EabCredentials
        {
            EabKeyId = "key-id-123",
            EabKey = "base64-key-value",
            EabKeyAlg = "HS256"
        };

        Assert.Equal("key-id-123", creds.EabKeyId);
        Assert.Equal("base64-key-value", creds.EabKey);
        Assert.Equal("HS256", creds.EabKeyAlg);
    }
}
