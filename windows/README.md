# Building Crowdsec for Windows

We provide scripts for PowerShell Core (>=v7.0). You can install it from [The latest GitHub releases](https://github.com/PowerShell/PowerShell/releases). Download the appropriate .msi file and execute it.

Now, run PowerShell as Administrator, go in the crowdsec repository (if you
already cloned it) and run:

```powershell
PS C:\Users\johndoe\src\crowdsec> powershell .\windows\install_dev_windows.ps1
[...]
```

If you don't have git you can download the script and execute it, it will
install git for you.

Now you should have the right dependencies (go, gcc, git). You can verify with
`choco list --localonly`. This is enough to build from sources, but if you want
to also build the choco or MSI packages, you need more dependencies:

```powershell
PS C:\Users\johndoe\src\crowdsec> powershell .\windows\install_installer_windows.ps1
[...]
```

You can now use

* `make` to build cmd\crowdsec\crowdsec.exe and cmd\crowdsec-cli\cscli.exe
* `make test` to run unit tests. Some tests requiring localstack are disabled. Functional tests are also only available on unix systems.

* `make windows_installer` to build a `crowdsec_x.y.z.msi` installer
* `make chocolatey` to build a package under `.\windows\Chocolatey\crowdsec\crowdsec_x.y.z.nupkg` which you can test using `choco install <filename>`

After installing CrowdSec, the binaries are in `C:\Program Files\CrowdSec\`:

```powershell
PS C:\Users\johndoe\src\crowdsec> & 'C:\Program Files\CrowdSec\cscli.exe' metrics
[...]
PS C:\Users\johndoe\src\crowdsec> & 'C:\Program Files\CrowdSec\cscli.exe' parsers install crowdsecurity/syslog-logs
[...]
```

To start/stop the service:

```powershell
PS C:\Users\johndoe\src\crowdsec> net stop crowdsec
The CrowdSec service is stopping..
The CrowdSec service was stopped successfully.
PS C:\Users\johndoe\src\crowdsec> net start crowdsec
The CrowdSec service is starting.
The CrowdSec service was started successfully.
```
