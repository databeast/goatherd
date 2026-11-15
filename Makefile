GO ?= go
DOCKER ?= docker
CAPTURE_BINARY ?= build/goatherd
COORDINATOR_HOST ?= $(shell hostname -f 2>/dev/null || hostname)
export COORDINATOR_HOST
MUTATION_PATH ?= .
GREMLINS_FLAGS ?= --workers 1

.DEFAULT_GOAL := help
.PHONY: help build static deploy capture-grant capture-status capture-revoke test cover vet fmt mutation

help:
	@echo "make build     Build the goatherd executable in src"
	@echo "make static    Build a static Linux executable in build/goatherd using Docker"
	@echo "make deploy    Build a fresh coordinator and sensor pair on Linux"
	@echo "               Override COORDINATOR_HOST with the reachable DNS name or IP"
	@echo "make capture-grant   Grant Linux CAP_NET_RAW to CAPTURE_BINARY (requires privilege)"
	@echo "make capture-status  Show file capabilities on CAPTURE_BINARY"
	@echo "make capture-revoke  Remove file capabilities from CAPTURE_BINARY (requires privilege)"
	@echo "make test      Run all Go tests"
	@echo "make cover     Run tests with package coverage"
	@echo "make vet       Run go vet"
	@echo "make fmt       Format Go packages"
	@echo "make mutation  Run Gremlins mutation tests"
	@echo "               Override MUTATION_PATH and GREMLINS_FLAGS as needed"

build:
	cd src && $(GO) build .

static:
	$(DOCKER) build --target static-export --output type=local,dest=build .

deploy:
	$(DOCKER) build --target deployment-builder -t goatherd-deployment-builder .
	mkdir -p build
	mkdir -m 700 build/deployment
	$(DOCKER) run --rm --user "$$(id -u):$$(id -g)" --tmpfs /work:rw,nosuid,exec,mode=1777,size=2g -e COORDINATOR_HOST -e GOCACHE=/work/cache -e GOTMPDIR=/work -v "$(CURDIR)/build/deployment:/out" goatherd-deployment-builder /out

capture-grant:
	setcap cap_net_raw=ep "$(CAPTURE_BINARY)"

capture-status:
	getcap -v "$(CAPTURE_BINARY)"

capture-revoke:
	setcap -r "$(CAPTURE_BINARY)"

test:
	cd src && $(GO) test ./...

cover:
	cd src && $(GO) test -cover ./...

vet:
	cd src && $(GO) vet ./...

fmt:
	cd src && $(GO) fmt ./...

mutation:
	cd src && $(GO) tool gremlins unleash $(MUTATION_PATH) $(GREMLINS_FLAGS)
