// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class OptionsValidationTests
{
    [Fact]
    public void Validate_WithNonWildcardDomains_ReturnsSuccess()
    {
        var validation = new OptionsValidation();
        var options = new LettuceEncryptOptions
        {
            DomainNames = new[] { "example.com", "www.example.com" }
        };

        var result = validation.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_WithWildcardDomain_ReturnsFail()
    {
        var validation = new OptionsValidation();
        var options = new LettuceEncryptOptions
        {
            DomainNames = new[] { "*.example.com" },
            AllowedChallengeTypes = ChallengeType.Http01
        };

        var result = validation.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("*", result.FailureMessage);
    }

    [Fact]
    public void Validate_WithWildcardDomain_AndDns01Challenge_ReturnsSuccess()
    {
        var validation = new OptionsValidation();
        var options = new LettuceEncryptOptions
        {
            DomainNames = new[] { "*.example.com" },
            AllowedChallengeTypes = ChallengeType.Dns01
        };

        var result = validation.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_WithEmptyDomainNames_ReturnsSuccess()
    {
        var validation = new OptionsValidation();
        var options = new LettuceEncryptOptions
        {
            DomainNames = Array.Empty<string>()
        };

        var result = validation.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_WithMixedDomainsIncludingWildcard_ReturnsFail()
    {
        var validation = new OptionsValidation();
        var options = new LettuceEncryptOptions
        {
            DomainNames = new[] { "example.com", "*.example.com" },
            AllowedChallengeTypes = ChallengeType.Http01
        };

        var result = validation.Validate(null, options);

        Assert.True(result.Failed);
    }

    [Fact]
    public void Validate_WithTlsAlpn01ChallengeAndWildcard_ReturnsFail()
    {
        var validation = new OptionsValidation();
        var options = new LettuceEncryptOptions
        {
            DomainNames = new[] { "*.example.com" },
            AllowedChallengeTypes = ChallengeType.TlsAlpn01
        };

        var result = validation.Validate(null, options);

        Assert.True(result.Failed);
    }

    [Fact]
    public void Validate_WithAnyChallengeTypeAndWildcard_ReturnsFail()
    {
        var validation = new OptionsValidation();
        var options = new LettuceEncryptOptions
        {
            DomainNames = new[] { "*.example.com" },
            AllowedChallengeTypes = ChallengeType.Any
        };

        var result = validation.Validate(null, options);

        Assert.True(result.Failed);
    }

    [Fact]
    public void Validate_WithNameParameter()
    {
        var validation = new OptionsValidation();
        var options = new LettuceEncryptOptions
        {
            DomainNames = new[] { "example.com" }
        };

        var result = validation.Validate("TestName", options);

        Assert.True(result.Succeeded);
    }
}
