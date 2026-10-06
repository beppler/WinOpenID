using WinOpenID.UserDirectory;

namespace WinOpenID.Tests.UserDirectory;

// Directory with the users of the tests, indexed by SID
public class FakeDirectory : IDirectory
{
    // Domain user with all the attributes and groups
    public static readonly DirectoryUser CompleteUser = new()
    {
        Sid = "S-1-5-21-1000-2000-3000-1104",
        Guid = new Guid("0f6c3a2e-9b1d-4c5e-8f7a-1b2c3d4e5f60"),
        DisplayName = "Maria da Silva",
        GivenName = "Maria",
        Surname = "da Silva",
        EmployeeId = "12345",
        EmailAddress = "maria@example.com",
        PhoneNumber = "+55 11 5555-0100",
        Groups = ["Domain Users", "Developers"]
    };

    // Local account without the optional attributes and groups
    public static readonly DirectoryUser MinimalUser = new()
    {
        Sid = "S-1-5-21-1000-2000-3000-1001"
    };

    private readonly Dictionary<string, DirectoryUser> users;

    public FakeDirectory(params DirectoryUser[] users)
    {
        this.users = (users.Length == 0 ? [CompleteUser, MinimalUser] : users).ToDictionary(user => user.Sid, StringComparer.Ordinal);
    }

    // Calls received, to check that the groups are only loaded when requested
    public List<(string Sid, bool IncludeGroups)> Calls { get; } = [];

    public Task<DirectoryUser> FindBySidAsync(string sid, bool includeGroups, CancellationToken cancellationToken = default)
    {
        Calls.Add((sid, includeGroups));

        if (sid == null || !users.TryGetValue(sid, out DirectoryUser user))
        {
            return Task.FromResult<DirectoryUser>(null);
        }

        return Task.FromResult(includeGroups ? user : user with { Groups = [] });
    }
}
