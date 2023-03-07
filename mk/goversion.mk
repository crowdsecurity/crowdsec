
MINIMUM_MAJOR ?= 1
MINIMUM_MINOR ?= 20

BUILD_GOVERSION = $(subst go,,$(shell go env GOVERSION))

go_major_minor = $(subst ., ,$(BUILD_GOVERSION))
GO_MAJOR_VERSION = $(word 1, $(go_major_minor))
GO_MINOR_VERSION = $(word 2, $(go_major_minor))

GO_VERSION_VALIDATION_ERR_MSG = Golang version ($(BUILD_GOVERSION)) is not supported, please use at least $(MINIMUM_MAJOR).$(MINIMUM_MINOR)

.PHONY: goversion
goversion:
ifneq ($(OS), Windows_NT)
	@if [ $(GO_MAJOR_VERSION) -gt $(MINIMUM_MAJOR) ]; then \
		exit 0; \
	elif [ $(GO_MAJOR_VERSION) -lt $(MINIMUM_MAJOR) ]; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	elif [ $(GO_MINOR_VERSION) -lt $(MINIMUM_MINOR) ] ; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	fi
else
	# This needs Set-ExecutionPolicy -Scope CurrentUser Unrestricted
	@$(CS_ROOT)/mk/check_go_version.ps1 $(MINIMUM_MAJOR) $(MINIMUM_MINOR)
endif
