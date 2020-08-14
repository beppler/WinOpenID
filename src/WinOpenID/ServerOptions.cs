using System;
using System.Linq;

namespace WinOpenID
{
    public class ServerOptions
    {
        public const string Server = nameof(Server);

        public string[] AllowedHosts { get; set; } = Array.Empty<string>();

        public string[] AllowerOrigins => AllowedHosts?.Select(x => new Uri(x).GetLeftPart(UriPartial.Authority)).ToArray();

        public string Domain { get; set; }

        public bool UseDomain => !string.IsNullOrWhiteSpace(Domain);

        public bool EncryptAccessToken { get; set; }
    }
}
