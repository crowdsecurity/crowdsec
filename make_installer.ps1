go-msi make --msi crowdsec.msi --version 0.0.1 -s .\windows\installer\ --arch amd64
go-msi choco --out choco --version 0.0.1 -s .\windows\choco\ -i crowdsec.msi 
