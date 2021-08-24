choco install -y wixtoolset
$env:Path += ";C:\Program Files (x86)\WiX Toolset v3.11\bin"
go-msi make --msi crowdsec.msi --version 0.0.1 -s .\windows\installer\