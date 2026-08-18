#!/usr/bin/env bash
# Build a .deb for Signet.
#
#   ./packaging/build-deb.sh VERSION ARCH PATH-TO-BINARY
#
# Deliberately plain dpkg-deb rather than a packaging framework: this produces
# one binary, one unit file, and one directory, and a framework would be more
# moving parts than the thing being packaged.
set -euo pipefail

VERSION="${1:?usage: build-deb.sh VERSION ARCH BINARY}"
ARCH="${2:?}"
BINARY="${3:?}"

PKG="signet_${VERSION}_${ARCH}"
ROOT="$(mktemp -d)/$PKG"
trap 'rm -rf "$(dirname "$ROOT")"' EXIT

install -Dm0755 "$BINARY"                     "$ROOT/usr/bin/signet"
install -Dm0644 packaging/debian/signet.service "$ROOT/lib/systemd/system/signet.service"
install -Dm0644 LICENSE                       "$ROOT/usr/share/doc/signet/LICENSE"
install -Dm0644 NOTICE                        "$ROOT/usr/share/doc/signet/NOTICE"
install -Dm0644 README.md                     "$ROOT/usr/share/doc/signet/README.md"
install -Dm0644 SECURITY.md                   "$ROOT/usr/share/doc/signet/SECURITY.md"
install -Dm0644 packaging/debian/signet.env   "$ROOT/usr/share/doc/signet/signet.env.example"

mkdir -p "$ROOT/DEBIAN"
INSTALLED_KB=$(du -sk "$ROOT" | cut -f1)

cat > "$ROOT/DEBIAN/control" <<EOF
Package: signet
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Maintainer: Mark Carey <mcarey@solcore.net>
Installed-Size: $INSTALLED_KB
Depends: adduser
Homepage: https://github.com/mcarey42/signet
Description: Identity, PKI, authorization and secrets in one binary
 Signet is a single-binary authority: a Vault-compatible KV API, an internal
 certificate authority, an OIDC issuer and an SSH certificate authority, all
 expressing one authorization decision.
 .
 This is a pre-1.0 release and is not recommended for production. See
 /usr/share/doc/signet/README.md and the open findings register in the
 project repository before deploying it.
EOF

# The package creates a system user and a data directory, and nothing else. It
# does NOT enable or start the service: a secrets authority should be
# configured deliberately before it runs, not started by an apt-get.
cat > "$ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  configure)
    if ! getent passwd signet >/dev/null; then
      adduser --system --group --home /var/lib/signet \
              --no-create-home --quiet --shell /usr/sbin/nologin signet
    fi
    install -d -o signet -g signet -m 0700 /var/lib/signet
    install -d -o root   -g signet -m 0750 /etc/signet
    if [ ! -e /etc/signet/signet.env ]; then
      cp /usr/share/doc/signet/signet.env.example /etc/signet/signet.env
      chown root:signet /etc/signet/signet.env
      chmod 0640 /etc/signet/signet.env
    fi
    echo "signet: installed but NOT started."
    echo "signet: initialize a domain first —"
    echo "signet:   sudo -u signet signet genesis -data-dir /var/lib/signet"
    echo "signet: then: systemctl enable --now signet"
    ;;
esac
exit 0
EOF
chmod 0755 "$ROOT/DEBIAN/postinst"

cat > "$ROOT/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && command -v systemctl >/dev/null; then
  systemctl stop signet.service 2>/dev/null || true
fi
exit 0
EOF
chmod 0755 "$ROOT/DEBIAN/prerm"

# /var/lib/signet is deliberately NOT removed on purge. It holds the sealed
# store and the seal key; deleting it destroys every secret in the domain, and
# an apt-get purge is not the moment to make that decision for someone.
cat > "$ROOT/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = purge ]; then
  echo "signet: /var/lib/signet has been left in place."
  echo "signet: it holds the sealed store and the seal key — removing it destroys"
  echo "signet: every secret in this domain. Delete it yourself if that is what you want."
fi
exit 0
EOF
chmod 0755 "$ROOT/DEBIAN/postrm"

# Written relative to the invoking directory, which is the repo root in CI.
OUT="$PWD/$PKG.deb"
dpkg-deb --build --root-owner-group "$ROOT" "$OUT" >/dev/null
ls -1 "$OUT"
