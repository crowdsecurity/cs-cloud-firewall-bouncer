# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get


PREFIX?="/"
PID_DIR = $(PREFIX)"/var/run/"
BINARY_NAME=cs-cloud-firewall-bouncer


#Current versioning information from env
BUILD_VERSION?="$(shell git describe --tags `git rev-list --tags --max-count=1`)"
BUILD_GOVERSION="$(shell go version | cut -d " " -f3 | sed -r 's/[go]+//g')"
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
BUILD_TAG="$(shell git rev-parse HEAD)"
export LD_OPTS=-ldflags "-s -w -X github.com/fallard84/cs-cloud-firewall-bouncer/pkg/version.Version=$(BUILD_VERSION) \
-X github.com/fallard84/cs-cloud-firewall-bouncer/pkg/version.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/fallard84/cs-cloud-firewall-bouncer/pkg/version.Tag=$(BUILD_TAG) \
-X github.com/fallard84/cs-cloud-firewall-bouncer/pkg/version.GoVersion=$(BUILD_GOVERSION)"

RELDIR = "cs-cloud-firewall-bouncer-${BUILD_VERSION}"


all: clean test build

build: clean
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v

test:
	@$(GOTEST) -v github.com/fallard84/cs-cloud-firewall-bouncer/pkg/...

clean:
	@rm -f $(BINARY_NAME)
	@rm -rf ${RELDIR}
	@rm -f cs-cloud-firewall-bouncer.tgz || ""


.PHONY: release
release: build
	@if [ -z ${BUILD_VERSION} ] ; then BUILD_VERSION="local" ; fi
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, clean" ;  exit 1 ; fi
	@echo Building Release to dir $(RELDIR)
	@mkdir $(RELDIR)/
	@cp $(BINARY_NAME) $(RELDIR)/
	@cp -R ./config $(RELDIR)/
	@cp ./scripts/install.sh $(RELDIR)/
	@cp ./scripts/uninstall.sh $(RELDIR)/
	@cp ./scripts/upgrade.sh $(RELDIR)/
	@chmod +x $(RELDIR)/install.sh
	@chmod +x $(RELDIR)/uninstall.sh
	@chmod +x $(RELDIR)/upgrade.sh
	@tar cvzf cs-cloud-firewall-bouncer.tgz $(RELDIR)
	