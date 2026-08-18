# The source tree lives on an NFS mount whose server does not support flock, and
# the Go toolchain locks go.mod in place during module operations. So build and
# test from a local-disk mirror, then copy the resolved module files back.
#
# Set BUILD_DIR to any local path. If the tree is already on local disk you can
# run the plain go commands directly; these targets stay correct either way.

BUILD_DIR ?= $(TMPDIR)signet-build
BIN       ?= $(BUILD_DIR)/signet
SYNC       = rsync -a --delete --exclude '.git' --exclude '._*' --exclude '.remember' ./ $(BUILD_DIR)/

.PHONY: all build test vet fmt tidy demo clean

all: test build

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

build: $(BUILD_DIR)
	@$(SYNC)
	@cd $(BUILD_DIR) && go build -o signet ./cmd/signet
	@echo "built $(BIN) ($$(du -h $(BIN) | cut -f1))"

test: $(BUILD_DIR)
	@$(SYNC)
	@cd $(BUILD_DIR) && go test ./...

vet: $(BUILD_DIR)
	@$(SYNC)
	@cd $(BUILD_DIR) && go vet ./...

fmt:
	@gofmt -l -w .

# tidy resolves modules on local disk, then brings go.mod/go.sum back.
tidy: $(BUILD_DIR)
	@$(SYNC)
	@cd $(BUILD_DIR) && go mod tidy
	@cp $(BUILD_DIR)/go.mod $(BUILD_DIR)/go.sum ./

clean:
	@rm -rf $(BUILD_DIR)

# Hardware-seal tests against a SoftHSM token. SoftHSM implements the same
# PKCS#11 interface a real HSM does, so this exercises the production code path
# rather than a mock. Requires cgo and the pkcs11 build tag.
SOFTHSM_MODULE ?= /opt/homebrew/lib/softhsm/libsofthsm2.so
# Deliberately outside BUILD_DIR: the build mirror is rsynced with --delete,
# which would wipe the token between creating it and using it.
SOFTHSM_DIR    ?= $(TMPDIR)signet-softhsm

.PHONY: softhsm test-hsm build-hsm

softhsm:
	@rm -rf $(SOFTHSM_DIR) && mkdir -p $(SOFTHSM_DIR)/tokens
	@printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$(SOFTHSM_DIR)" > $(SOFTHSM_DIR)/softhsm2.conf
	@SOFTHSM2_CONF=$(SOFTHSM_DIR)/softhsm2.conf softhsm2-util --init-token --free \
		--label signet --pin 1234 --so-pin 5678 >/dev/null
	@SOFTHSM2_CONF=$(SOFTHSM_DIR)/softhsm2.conf pkcs11-tool --module $(SOFTHSM_MODULE) \
		--login --pin 1234 --keygen --key-type aes:32 --label signet-seal --usage-decrypt >/dev/null 2>&1
	@echo "token ready: $(SOFTHSM_DIR)/softhsm2.conf"

test-hsm: $(BUILD_DIR) softhsm
	@$(SYNC)
	@cd $(BUILD_DIR) && CGO_ENABLED=1 \
		SOFTHSM2_CONF=$(SOFTHSM_DIR)/softhsm2.conf \
		SIGNET_TEST_PKCS11='pkcs11:?module=$(SOFTHSM_MODULE)&token=signet&pin=1234&label=signet-seal' \
		go test -tags pkcs11 ./internal/seal/

# A binary with hardware-seal support. Needs cgo, so it is not the static
# default build.
build-hsm: $(BUILD_DIR)
	@$(SYNC)
	@cd $(BUILD_DIR) && CGO_ENABLED=1 go build -tags pkcs11 -o signet-hsm ./cmd/signet
	@echo "built $(BUILD_DIR)/signet-hsm"

# End-to-end trust bundle ceremony: offline root -> two issuers -> signed
# bundle -> two consumers choosing different anchors, verified with openssl.
.PHONY: test-trust
test-trust: build
	@cp $(BIN) ./signet-testbin
	@BIN=$(PWD)/signet-testbin ./test/trust/run.sh; s=$$?; rm -f ./signet-testbin; exit $$s
