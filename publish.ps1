dotnet publish -c Release -r win10-x64 -o .\dist\Release
Copy-Item .\src\WinOpenID\appsettings.Production.json .\dist\Release