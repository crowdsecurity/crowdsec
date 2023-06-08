# Windows specific

MAKE=make
GOOS=windows
PREFIX=$(shell $$env:TEMP)

#Current versioning information from env
#BUILD_VERSION?=$(shell (Invoke-WebRequest -UseBasicParsing -Uri https://api.github.com/repos/crowdsecurity/crowdsec/releases/latest).Content | jq -r '.tag_name')
#hardcode it till i find a workaround
BUILD_VERSION?=$(shell git describe --tags $$(git rev-list --tags --max-count=1))
BUILD_TIMESTAMP?=$(shell Get-Date -Format "yyyy-MM-dd_HH:mm:ss")
DEFAULT_CONFIGDIR?=C:\\ProgramData\\CrowdSec\\config
DEFAULT_DATADIR?=C:\\ProgramData\\CrowdSec\\data

#please tell me there is a better way to completly ignore errors when trying to delete a file....
RM=Remove-Item -ErrorAction Ignore -Recurse
CP=Copy-Item
CPR=Copy-Item -Recurse
MKDIR=New-Item -ItemType directory
WIN_IGNORE_ERR=; exit 0
