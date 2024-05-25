ifeq ($(OS), Windows_NT)
	SHELL := pwsh.exe
	.SHELLFLAGS := -NoProfile -Command
	EXT = .exe
endif

GO = go
GOBUILD = $(GO) build
GOTEST = $(GO) test

CROWDSEC_BIN = crowdsec$(EXT)
# names longer than 15 chars break 'pgrep'

.PHONY: all
all: clean test build

build: clean
	$(GOBUILD) $(LD_OPTS) -o $(CROWDSEC_BIN)

test:
	$(GOTEST) $(LD_OPTS) -v ./...

clean:
	@$(RM) $(CROWDSEC_BIN) $(WIN_IGNORE_ERR)
