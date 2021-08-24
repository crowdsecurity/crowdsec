#install choco
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
choco install -y golang 
choco install -y jq 
choco install -y git
choco install -y mingw
refreshenv
git clone https://github.com/zecloud/crowdsec
cd .\crowdsec
mkdir  config\hub\
mkdir  data\
mkdir  config\logs\
cd .\cmd\crowdsec\
go build 
cd ..\crowdsec-cli\
go build 
.\crowdsec-cli.exe -c ..\..\config\config_win.yaml hub update -b master
.\crowdsec-cli.exe -c ..\..\config\config_win.yaml machines add -a
.\crowdsec-cli.exe -c ..\..\config\config_win.yaml capi register
cd ..\crowdsec\
.\crowdsec.exe -c ..\..\config\config_win.yaml
