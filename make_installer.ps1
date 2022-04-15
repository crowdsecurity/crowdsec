param (
    $version
)
$env:Path += ";C:\Program Files (x86)\WiX Toolset v3.11\bin"
if ($version.StartsWith("v"))
{
    $version = $version.Substring(1)
}
Remove-Item -Force -Recurse -Path .\msi -ErrorAction SilentlyContinue
#we only harvest the patterns dir, as we want to handle differently some yaml files in the config directory, and I really don't want to write xlst filters to exclude the files :(
heat.exe dir config\patterns -nologo -cg CrowdsecPatterns -dr PatternsDir -g1 -gg -sf -srd -scom -sreg -out "msi\fragment.wxs"
candle.exe -arch x64 -dSourceDir=config\patterns -dVersion="$version" -out msi\ msi\fragment.wxs windows\installer\WixUI_HK.wxs windows\installer\product.wxs
light.exe -b .\config\patterns -ext WixUIExtension -ext WixUtilExtension -sacl -spdb  -out crowdsec_$version.msi msi\fragment.wixobj msi\WixUI_HK.wixobj msi\product.wixobj