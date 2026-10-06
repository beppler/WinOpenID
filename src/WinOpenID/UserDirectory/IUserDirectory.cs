namespace WinOpenID.UserDirectory;

// Directory where the users authenticated by Windows are searched
public interface IUserDirectory
{
    // Finds the user by SID (unique, unlike user names that can clash on trusted domains); returns null if not found.
    // Loading the groups is expensive, so they are only loaded when includeGroups is true.
    Task<DirectoryUser> FindBySidAsync(string sid, bool includeGroups, CancellationToken cancellationToken = default);
}
