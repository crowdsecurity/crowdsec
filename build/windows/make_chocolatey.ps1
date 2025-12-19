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

Set-Location (Join-Path $env:BUILD_SOURCESDIRECTORY 'build\windows\Chocolatey\crowdsec')
Copy-Item (Join-Path $env:BUILD_SOURCESDIRECTORY "crowdsec_$version.msi") "tools\crowdsec.msi"

choco pack --version $version

Copy-Item "crowdsec.$version.nupkg" (Join-Path $env:BUILD_SOURCESDIRECTORY ".")
