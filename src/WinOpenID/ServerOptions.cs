using System;

namespace WinOpenID
{
    public class ServerOptions
    {
        public const string Server = nameof(Server);

        public string[] AllowedHosts { get; set; } = Array.Empty<string>();

        public string Domain { get; set; }

        public bool UseDomain => !string.IsNullOrWhiteSpace(Domain);

        public bool EncryptAccessToken { get; set; }
    }
}
