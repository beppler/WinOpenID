namespace WinOpenID;

// User attributes read from the directory (Active Directory or local machine accounts)
public sealed record DirectoryUser
{
    // Security identifier (SID) in the string format, e.g. S-1-5-21-...
    public required string Sid { get; init; }

    // Object GUID, only available for directory (domain) accounts
    public Guid? Guid { get; init; }

    public string DisplayName { get; init; }

    public string GivenName { get; init; }

    public string Surname { get; init; }

    public string EmployeeId { get; init; }

    public string EmailAddress { get; init; }

    public string PhoneNumber { get; init; }

    // Names of the groups of the user, including the nested ones (only loaded when requested)
    public IReadOnlyList<string> Groups { get; init; } = [];
}
