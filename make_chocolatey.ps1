param (
    $version
)
if ($version.StartsWith("v"))
{
    $version = $version.Substring(1)
}

#Pre-releases will be like 1.4.0-rc1, remove everything after the dash as it does not conform to the MSI versioning scheme
if ($version.Contains("-")) 
{
    $version = $version.Substring(0, $version.IndexOf("-"))
}

Set-Location .\windows\Chocolatey\crowdsec
Copy-Item ..\..\..\crowdsec_$version.msi tools\crowdsec.msi

choco pack --version $version