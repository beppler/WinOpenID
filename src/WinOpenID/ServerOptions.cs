using System;
using System.Linq;

namespace WinOpenID
{
    public class ServerOptions
    {
        public const string Server = nameof(Server);

        private string[] allowedHosts = Array.Empty<string>();
        public string[] AllowedHosts
        {
            get => allowedHosts;
            set
            {
                var hosts = value ?? Array.Empty<string>();
                AllowedOrigins = hosts.Select(x => new Uri(x).GetLeftPart(UriPartial.Authority)).ToArray() ?? Array.Empty<string>();
                allowedHosts = hosts;
            }
        }

        public string[] AllowedOrigins { get; private set; } = Array.Empty<string>();

        public string Domain { get; set; }

        public bool UseDomain => !string.IsNullOrWhiteSpace(Domain);

        public bool EncryptAccessToken { get; set; }
    }
}
