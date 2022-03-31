param (
    $version
)
if ($version.StartsWith("v"))
{
    $version = $version.Substring(1)
}

Set-Location .\windows\Chocolatey\crowdsec
Copy-Item ..\..\..\crowdsec_$version.msi tools\crowdsec.msi

choco pack