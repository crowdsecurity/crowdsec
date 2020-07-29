# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

CROWDSEC_BIN=crowdsec
PREFIX?="/"
CFG_PREFIX = $(PREFIX)"/etc/crowdsec/config/"
BIN_PREFIX = $(PREFIX)"/usr/local/bin/"
DATA_PREFIX = $(PREFIX)"/var/run/crowdsec/"
PID_DIR = $(PREFIX)"/var/run/"

SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec.service"

all: clean test build

build: clean
	$(GOBUILD) $(LD_OPTS) -o $(CROWDSEC_BIN) -v

static: clean
	$(GOBUILD) -o $(CROWDSEC_BIN) -v -a -tags netgo -ldflags '-w -extldflags "-static"'

test:
	$(GOTEST) -v ./...

clean:
	rm -f $(CROWDSEC_BIN)

.PHONY: install
install: install-conf install-bin

.PHONY: install-conf
install-conf:
	mkdir -p $(DATA_PREFIX) || exit
	(cd ../.. / && find ./data -type f -exec install -Dm 755 "{}" "$(DATA_PREFIX){}" \; && cd ./cmd/crowdsec) || exit
	(cd ../../config && find ./patterns -type f -exec install -Dm 755 "{}" "$(CFG_PREFIX){}" \; && cd ../cmd/crowdsec) || exit
	mkdir -p "$(CFG_PREFIX)" || exit
	mkdir -p "$(CFG_PREFIX)/parsers" || exit
	mkdir -p "$(CFG_PREFIX)/scenarios" || exit
	mkdir -p "$(CFG_PREFIX)/postoverflows" || exit
	mkdir -p "$(CFG_PREFIX)/collections" || exit
	mkdir -p "$(CFG_PREFIX)/patterns" || exit
	install -v -m 755 -D ../../config/prod.yaml "$(CFG_PREFIX)" || exit
	install -v -m 755 -D ../../config/dev.yaml "$(CFG_PREFIX)" || exit
	install -v -m 755 -D ../../config/acquis.yaml "$(CFG_PREFIX)" || exit
	install -v -m 755 -D ../../config/profiles.yaml "$(CFG_PREFIX)" || exit
	install -v -m 755 -D ../../config/api.yaml "$(CFG_PREFIX)" || exit
	mkdir -p $(PID_DIR) || exit
	PID=$(PID_DIR) DATA=$(DATA_PREFIX)"/data/" CFG=$(CFG_PREFIX) envsubst < ../../config/prod.yaml > $(CFG_PREFIX)"/default.yaml"	

.PHONY: install-bin
install-bin:
	install -v -m 755 -D "$(CROWDSEC_BIN)" "$(BIN_PREFIX)/$(CROWDSEC_BIN)" || exit

.PHONY: systemd"$(BIN_PREFI"$(BIN_PREFIX)/$(CROWDSEC_BIN)""$(BIN_PREFIX)/$(CROWDSEC_BIN)"X)/$(CROWDSEC_BIN)"
systemd: install
	CFG=$(CFG_PREFIX) PID=$(PID_DIR) BIN=$(BIN_PREFIX)"/"$(CROWDSEC_BIN) envsubst < ../../config/crowdsec.service > "$(SYSTEMD_PATH_FILE)"
	systemctl daemon-reload

.PHONY: uninstall
uninstall:
	rm -rf $(CFG_PREFIX)
	rm -rf $(DATA_PREFIX)
	rm -f "$(BIN_PREFIX)/$(CROWDSEC_BIN)"
	rm -f "$(SYSTEMD_PATH_FILE)"
