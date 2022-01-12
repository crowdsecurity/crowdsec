**POC Windows version of crowdsec**

To  test and develop on windows first execute the script that will install all required tools for windows [install dev on windows](/windows/install_dev_windows.ps1)
copy the script locally open a powershell window or launch powershell from command line 
powershell
./install_dev_windows.ps1
when all the required packages are installed 
Clone the project and build manually the client and the cli
in cmd/crowdsec and cmd/crowdsec-cli with go build
you should now have a crowdsec.exe and crowdsec-cli.exe

To make the installer and package first install the packages required executing the script 
 [install installer on windows](/windows/install_installer_windows.ps1)

And finally to create the choco package and msi execute the script at root level 
 [make installer](/install_installer_windows.ps1) 
 ./make_installer.ps1

You should now have a CrowdSec.0.0.1.nupkg file 
you can test it using 
choco install CrowdSec.0.0.1.nupkg 
it will install and configure crowdsec for windows. 

To test it navigate to C:\Program Files\CrowdSec and test the cli 
.\crowdsec-cli.exe metrics

Install something from the hub 
.\crowdsec-cli.exe parsers install crowdsecurity/syslog-logs

and restart the windows service 
net start crowdsec 
net stop crowdsec
