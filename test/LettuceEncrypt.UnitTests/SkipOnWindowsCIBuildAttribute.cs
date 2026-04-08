// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Xunit;

namespace LettuceEncrypt.UnitTests;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class SkipOnWindowsCIBuildAttribute : FactAttribute
{
    // Public constructor that accepts source information (satisfies xUnit analyzer xUnit3003).
    public SkipOnWindowsCIBuildAttribute([CallerFilePath] string sourceFilePath = "", [CallerLineNumber] int sourceLineNumber = 0)
        : base(sourceFilePath, sourceLineNumber)
    {
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CI"))
            && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Skip = "On Windows in CI, adding certs to store doesn't work for unclear reasons.";
        }
    }
}
