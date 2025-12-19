$ErrorActionPreference = 'Stop';
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$fileLocation = Join-Path $toolsDir 'crowdsec.msi'

$silentArgs = "/qn /norestart /l*v `"$($env:TEMP)\$($packageName).$($env:chocolateyPackageVersion).MsiInstall.log`""


$pp = Get-PackageParameters

if ($pp['AgentOnly']) {
  $silentArgs += " AGENT_ONLY=1"
}


$packageArgs = @{
  packageName   = $env:ChocolateyPackageName
  unzipLocation = $toolsDir
  fileType      = 'msi'
  file64         = $fileLocation
  softwareName  = 'Crowdsec'
  silentArgs    = $silentArgs
  validExitCodes= @(0, 3010, 1641)
}

Install-ChocolateyInstallPackage @packageArgs

if ($pp['AgentOnly']) {
  Write-Host "/AgentOnly was specified. LAPI is disabled, please register your agent manually and configure the service to start on boot."
}