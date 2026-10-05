#!/usr/bin/env -S dotnet --
#:property ManagePackageVersionsCentrally=false
#:package System.CommandLine@2.0.12
using System;
using System.CommandLine;
using System.Security.Cryptography;

var curveOption = new Option<string>("--curve", "-c")
{
    Description = "The name of the elliptic curve (e.g., nistP256, nistP384, nistP521).",
    DefaultValueFactory = _ => "nistP384"
};

var rootCommand = new RootCommand("ECDsa key generator utility.")
{
    curveOption
};


rootCommand.SetAction((ParseResult parseResult) =>
{
    string selectedCurve = parseResult.GetValue(curveOption)!;
    try
    {
        using var ecdsa = ECDsa.Create(ECCurve.CreateFromFriendlyName(selectedCurve));
        var bytes = ecdsa.ExportECPrivateKey();

        Console.WriteLine(Convert.ToBase64String(bytes));
    }
    catch (CryptographicException)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine($"Error: The curve '{selectedCurve}' is invalid or not supported by this system.");
        Console.ResetColor();
    }
});

return rootCommand.Parse(args).Invoke();
