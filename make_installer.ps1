##FIXME: Get version from arguments

$env:Path += ";C:\Program Files (x86)\WiX Toolset v3.11\bin"
#go-msi make --msi crowdsec.msi --version 0.0.1 -s .\windows\installer\ --arch amd64 -o  C:\Users\Seb\Documents\GitHub\crowdsec\msi
#go-msi choco --out choco --version 0.0.1 -s .\windows\choco\ -i crowdsec.msi
Remove-Item -Force -Recurse -Path .\msi
#we only harvest the patterns dir, as we want to handle differently some yaml files in the config directory, and I really don't want to write xlst filters to exclude the files :(
heat.exe dir config\patterns -nologo -cg CrowdsecPatterns -dr PatternsDir -g1 -gg -sf -srd -scom -sreg -out "msi\fragment.wxs"
candle.exe -arch x64 -dSourceDir=config\patterns -dVersion="1.2.3" -out msi\ msi\fragment.wxs windows\installer\WixUI_HK.wxs windows\installer\product.wxs
light.exe -b .\config\patterns -ext WixUIExtension -ext WixUtilExtension -sacl -spdb  -out crowdsec.msi msi\fragment.wixobj msi\WixUI_HK.wixobj msi\product.wixobj