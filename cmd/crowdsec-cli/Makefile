ifeq ($(OS), Windows_NT)
	SHELL := pwsh.exe
	.SHELLFLAGS := -NoProfile -Command
	EXT = .exe
endif

GO = go
GOBUILD = $(GO) build

BINARY_NAME = cscli$(EXT)
PREFIX ?= "/"
BIN_PREFIX = $(PREFIX)"/usr/local/bin/"

.PHONY: all
all: clean build

build: clean
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME)

.PHONY: install
install: install-conf install-bin

install-conf:

install-bin:
	@install -v -m 755 -D "$(BINARY_NAME)" "$(BIN_PREFIX)/$(BINARY_NAME)" || exit

uninstall:
	@$(RM) $(CSCLI_CONFIG) $(WIN_IGNORE_ERR)
	@$(RM) $(BIN_PREFIX)$(BINARY_NAME) $(WIN_IGNORE_ERR)

clean:
	@$(RM) $(BINARY_NAME) $(WIN_IGNORE_ERR)
