ifeq ($(OS), Windows_NT)
	SHELL := pwsh.exe
	.SHELLFLAGS := -NoProfile -Command
	EXT = .exe
endif

GO = go
GOBUILD = $(GO) build

BINARY_NAME = notification-splunk$(EXT)

build: clean
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME)

.PHONY: clean
clean:
	@$(RM) $(BINARY_NAME) $(WIN_IGNORE_ERR)
