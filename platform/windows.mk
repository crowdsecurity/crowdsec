# Windows specific
#

MAKE=make
GOOS=windows
PREFIX=$(shell $$env:TEMP)

GO_MAJOR_VERSION ?= $(shell (go env GOVERSION).replace("go","").split(".")[0])
GO_MINOR_VERSION ?= $(shell (go env GOVERSION).replace("go","").split(".")[1])
MINIMUM_SUPPORTED_GO_MAJOR_VERSION = 1
MINIMUM_SUPPORTED_GO_MINOR_VERSION = 17
GO_VERSION_VALIDATION_ERR_MSG = Golang version ($(BUILD_GOVERSION)) is not supported, please use least $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION).$(MINIMUM_SUPPORTED_GO_MINOR_VERSION)
#Current versioning information from env
#BUILD_VERSION?=$(shell (Invoke-WebRequest -UseBasicParsing -Uri https://api.github.com/repos/crowdsecurity/crowdsec/releases/latest).Content | jq -r '.tag_name')
#hardcode it till i find a workaround
BUILD_VERSION?=$(shell git describe --tags $$(git rev-list --tags --max-count=1))
BUILD_GOVERSION?=$(shell (go env GOVERSION).replace("go",""))
BUILD_CODENAME?=alphaga
BUILD_TIMESTAMP?=$(shell Get-Date -Format "yyyy-MM-dd_HH:mm:ss")
BUILD_TAG?=$(shell git rev-parse HEAD)
DEFAULT_CONFIGDIR?=C:\\ProgramData\\CrowdSec\\config
DEFAULT_DATADIR?=C:\\ProgramData\\CrowdSec\\data

#please tell me there is a better way to completly ignore errors when trying to delete a file....
RM=Remove-Item -ErrorAction Ignore -Recurse
CP=Copy-Item
CPR=Copy-Item -Recurse
MKDIR=New-Item -ItemType directory
WIN_IGNORE_ERR=; exit 0


$(warning Building for windows)
