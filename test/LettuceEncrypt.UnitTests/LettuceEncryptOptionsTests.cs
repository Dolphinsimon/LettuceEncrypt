// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Acme;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class LettuceEncryptOptionsTests
{
    [Fact]
    public void DefaultValues_AreCorrect()
    {
        var options = new LettuceEncryptOptions();

        Assert.Empty(options.DomainNames);
        Assert.False(options.AcceptTermsOfService);
        Assert.Equal(string.Empty, options.EmailAddress);
        Assert.False(options.UseStagingServer);
        Assert.Empty(options.AdditionalIssuers);
        Assert.Null(options.FallbackCertificate);
        Assert.Equal(TimeSpan.FromDays(30), options.RenewDaysInAdvance);
        Assert.Equal(TimeSpan.FromDays(1), options.RenewalCheckPeriod);
        Assert.Equal(KeyAlgorithm.ES256, options.KeyAlgorithm);
        Assert.Null(options.KeySize);
        Assert.Equal(ChallengeType.Any, options.AllowedChallengeTypes);
        Assert.NotNull(options.EabCredentials);
    }

    [Fact]
    public void DomainNames_SetToNull_ThrowsArgumentNullException()
    {
        var options = new LettuceEncryptOptions();

        Assert.Throws<ArgumentNullException>(() => options.DomainNames = null!);
    }

    [Fact]
    public void DomainNames_CanBeSet()
    {
        var options = new LettuceEncryptOptions();
        var domains = new[] { "example.com", "www.example.com" };

        options.DomainNames = domains;

        Assert.Equal(domains, options.DomainNames);
    }

    [Fact]
    public void UseStagingServer_CanBeSetAndRead()
    {
        var options = new LettuceEncryptOptions();

        options.UseStagingServer = true;
        Assert.True(options.UseStagingServer);

        options.UseStagingServer = false;
        Assert.False(options.UseStagingServer);
    }

    [Fact]
    public void RenewDaysInAdvance_CanBeSetToNull()
    {
        var options = new LettuceEncryptOptions();
        options.RenewDaysInAdvance = null;

        Assert.Null(options.RenewDaysInAdvance);
    }

    [Fact]
    public void RenewalCheckPeriod_CanBeSetToNull()
    {
        var options = new LettuceEncryptOptions();
        options.RenewalCheckPeriod = null;

        Assert.Null(options.RenewalCheckPeriod);
    }

    [Fact]
    public void AllowedChallengeTypes_CanBeCombined()
    {
        var options = new LettuceEncryptOptions();

        options.AllowedChallengeTypes = ChallengeType.Http01 | ChallengeType.TlsAlpn01;

        Assert.True(options.AllowedChallengeTypes.HasFlag(ChallengeType.Http01));
        Assert.True(options.AllowedChallengeTypes.HasFlag(ChallengeType.TlsAlpn01));
        Assert.False(options.AllowedChallengeTypes.HasFlag(ChallengeType.Dns01));
    }
}
