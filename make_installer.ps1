$env:Path += ";C:\Program Files (x86)\WiX Toolset v3.11\bin"
#go-msi make --msi crowdsec.msi --version 0.0.1 -s .\windows\installer\ --arch amd64 -o  C:\Users\Seb\Documents\GitHub\crowdsec\msi
#go-msi choco --out choco --version 0.0.1 -s .\windows\choco\ -i crowdsec.msi
New-Item -ItemType Directory -Force -Path .\msi
heat.exe dir config -nologo -cg CrowdsecConfig -dr ConfigDir -g1 -gg -sf -srd -scom -sreg -out "msi\fragment.wxs"
candle.exe -arch x64 -dSourceDir=config -out msi\ msi\fragment.wxs windows\installer\WixUI_HK.wxs windows\installer\product.wxs
light.exe -b config -ext WixUIExtension -ext WixUtilExtension -sacl -spdb  -out crowdsec.msi msi\fragment.wixobj msi\WixUI_HK.wixobj msi\product.wixobj