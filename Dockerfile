# Signet is a single static binary with no runtime dependencies, so the image is
# the binary and nothing else — no shell, no package manager, no base-image CVE
# stream to track.
#
# Build the binary first (CGO_ENABLED=0), then:
#   docker build -t signet:dev --build-arg BIN=signet-linux .
FROM scratch

ARG BIN=signet-linux
COPY ${BIN} /signet

# The data directory must be a writable volume on local disk. NFS is a backup
# target, never a data dir — its locking is unreliable.
VOLUME ["/data"]
EXPOSE 8200

ENTRYPOINT ["/signet"]
CMD ["serve", "-data-dir", "/data", "-listen", "0.0.0.0:8200"]
