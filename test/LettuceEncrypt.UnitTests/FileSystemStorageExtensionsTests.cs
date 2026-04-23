// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class FileSystemStorageExtensionsTests
{
    [Fact]
    public void PersistDataToDirectory_ThrowsOnNullBuilder()
    {
        Assert.Throws<ArgumentNullException>(() =>
            FileSystemStorageExtensions.PersistDataToDirectory(null, new DirectoryInfo("/tmp/test"), "password"));
    }

    [Fact]
    public void PersistDataToDirectory_ThrowsOnNullDirectory()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var builder = services.AddLettuceEncrypt();

        Assert.Throws<ArgumentNullException>(() =>
            builder.PersistDataToDirectory(null, "password"));
    }

    [Fact]
    public void PersistDataToDirectory_RegistersServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var builder = services.AddLettuceEncrypt();
        var dir = new DirectoryInfo(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));

        try
        {
            builder.PersistDataToDirectory(dir, "testpassword");

            Assert.Contains(services, sd => sd.ServiceType == typeof(ICertificateRepository));
            Assert.Contains(services, sd => sd.ServiceType == typeof(ICertificateSource));
        }
        finally
        {
            if (dir.Exists) dir.Delete(true);
        }
    }

    [Fact]
    public void PersistDataToDirectory_DuplicateWithSamePassword_ReturnsWithoutError()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var builder = services.AddLettuceEncrypt();
        var dir = new DirectoryInfo(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));

        try
        {
            builder.PersistDataToDirectory(dir, "testpassword");
            // Second call with same password should succeed
            builder.PersistDataToDirectory(dir, "testpassword");
        }
        finally
        {
            if (dir.Exists) dir.Delete(true);
        }
    }

    [Fact]
    public void PersistDataToDirectory_DuplicateWithDifferentPassword_Throws()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var builder = services.AddLettuceEncrypt();
        var dir = new DirectoryInfo(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));

        try
        {
            builder.PersistDataToDirectory(dir, "password1");

            Assert.Throws<ArgumentException>(() =>
                builder.PersistDataToDirectory(dir, "password2"));
        }
        finally
        {
            if (dir.Exists) dir.Delete(true);
        }
    }
}
