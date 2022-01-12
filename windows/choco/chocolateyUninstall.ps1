$packageName = "{{.Choco.ID}}";
$fileType = 'msi';
$scriptPath =  $(Split-Path $MyInvocation.MyCommand.Path);
$fileFullPath = Join-Path $scriptPath '{{.Choco.MsiFile}}';

Uninstall-ChocolateyPackage $packageName $fileType "$fileFullPath /q"
