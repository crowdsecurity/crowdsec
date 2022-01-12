$packageName = '{{.Choco.ID}}'
$fileType = 'msi'
$silentArgs = '/quiet';
$scriptPath =  $(Split-Path $MyInvocation.MyCommand.Path);
$fileFullPath = Join-Path $scriptPath '{{.Choco.MsiFile}}';

Install-ChocolateyInstallPackage $packageName $fileType $silentArgs $fileFullPath -checksum '{{.Choco.MsiSum}}' -checksumType = 'sha256'
