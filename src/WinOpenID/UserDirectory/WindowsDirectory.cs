using Microsoft.Extensions.Options;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;

namespace WinOpenID.UserDirectory;

// Searches the users in the Active Directory domain (when Domain is set) or in the local machine accounts
public class WindowsDirectory : IDirectory
{
    private readonly WinOpenIDOptions serverOptions;

    public WindowsDirectory(IOptions<WinOpenIDOptions> serverOptions)
    {
        this.serverOptions = serverOptions?.Value ?? throw new ArgumentNullException(nameof(serverOptions));
    }

    public Task<DirectoryUser> FindBySidAsync(string sid, bool includeGroups, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(sid))
        {
            return Task.FromResult<DirectoryUser>(null);
        }

        var userSid = new SecurityIdentifier(sid);

        // Set the directory service to the active directory domain or machine
        using PrincipalContext directoryService = serverOptions.UseDomain
            ? new PrincipalContext(ContextType.Domain, serverOptions.Domain)
            : new PrincipalContext(ContextType.Machine);

        using UserPrincipal userInfo = UserPrincipal.FindByIdentity(directoryService, IdentityType.Sid, userSid.Value);

        // Defense in depth: make sure the account found is the authenticated one
        if (userInfo == null || userInfo.Sid != userSid)
        {
            return Task.FromResult<DirectoryUser>(null);
        }

        IReadOnlyList<string> groups = [];
        if (includeGroups)
        {
            using PrincipalSearchResult<Principal> authorizationGroups = userInfo.GetAuthorizationGroups();
            groups = [.. authorizationGroups.Select(group => group.Name)];
        }

        return Task.FromResult(new DirectoryUser
        {
            Sid = userInfo.Sid.Value,
            Guid = userInfo.Guid,
            DisplayName = userInfo.DisplayName,
            GivenName = userInfo.GivenName,
            Surname = userInfo.Surname,
            EmployeeId = userInfo.EmployeeId,
            EmailAddress = userInfo.EmailAddress,
            PhoneNumber = userInfo.VoiceTelephoneNumber,
            Groups = groups
        });
    }
}
