using Microsoft.Extensions.Options;

namespace WinOpenID.Tests;

// Only the checks done before searching the directory: the search itself requires Windows and the accounts or Active Directory
public class WindowsUserDirectoryTests
{
    [Fact]
    public void Constructor_RejectsNullOptions()
    {
        Assert.Throws<ArgumentNullException>(() => new WindowsUserDirectory(null));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task FindBySid_WithoutSid_ReturnsNull(string sid)
    {
        var directory = new WindowsUserDirectory(Options.Create(new WinOpenIDOptions()));

        Assert.Null(await directory.FindBySidAsync(sid, includeGroups: true, TestContext.Current.CancellationToken));
    }
}
