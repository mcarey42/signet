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
