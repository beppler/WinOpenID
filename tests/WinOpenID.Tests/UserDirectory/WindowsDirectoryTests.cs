using Microsoft.Extensions.Options;
using WinOpenID.UserDirectory;

namespace WinOpenID.Tests.UserDirectory;

// Only the checks done before searching the directory: the search itself requires Windows and the accounts or Active Directory
public class WindowsDirectoryTests
{
    [Fact]
    public void Constructor_RejectsNullOptions()
    {
        Assert.Throws<ArgumentNullException>(() => new WindowsDirectory(null));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task FindBySid_WithoutSid_ReturnsNull(string sid)
    {
        var directory = new WindowsDirectory(Options.Create(new WinOpenIDOptions()));

        Assert.Null(await directory.FindBySidAsync(sid, includeGroups: true, TestContext.Current.CancellationToken));
    }
}
