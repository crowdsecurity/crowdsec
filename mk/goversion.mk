
BUILD_GOVERSION=$(subst go,,$(shell go env GOVERSION))

MINIMUM_SUPPORTED_GO_MAJOR_VERSION = 1
MINIMUM_SUPPORTED_GO_MINOR_VERSION = 20

go_major_minor = $(subst ., ,$(BUILD_GOVERSION))
GO_MAJOR_VERSION = $(word 1, $(go_major_minor))
GO_MINOR_VERSION = $(word 2, $(go_major_minor))

GO_VERSION_VALIDATION_ERR_MSG = Golang version ($(BUILD_GOVERSION)) is not supported, please use at least $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION).$(MINIMUM_SUPPORTED_GO_MINOR_VERSION)

.PHONY: goversion
goversion:
ifneq ($(OS), Windows_NT)
	@if [ $(GO_MAJOR_VERSION) -gt $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		exit 0 ;\
	elif [ $(GO_MAJOR_VERSION) -lt $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	elif [ $(GO_MINOR_VERSION) -lt $(MINIMUM_SUPPORTED_GO_MINOR_VERSION) ] ; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	fi
else
	# This needs Set-ExecutionPolicy -Scope CurrentUser Unrestricted
	@$(CS_ROOT)/mk/check_go_version.ps1 $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) $(MINIMUM_SUPPORTED_GO_MINOR_VERSION)
endif
