#!/usr/bin/env bash
# One-time setup on the testbed machine (Linux Mint / Ubuntu / Debian, x86-64). Run as a NORMAL user:
#   ./setup_host.sh
# It asks for sudo only for apt. OpenSSL 3.5 is built into ~/opt/openssl-3.5 (nothing system-wide changes),
# the same prefix that ../certs.sh and the other measurement scripts use.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"   # absolute: later steps cd elsewhere
cd "$HERE"
OSSL_VER=${OSSL_VER:-3.5.4}
PREFIX=${PQC_OPENSSL:-$HOME/opt/openssl-3.5}

echo "== packages"
sudo apt-get update
sudo apt-get install -y build-essential perl iproute2 ethtool util-linux curl ca-certificates \
     python3 python3-matplotlib haproxy tcpdump cpufrequtils || true
# haproxy is only used by --topology proxy-*; keep the system service off
sudo systemctl disable --now haproxy 2>/dev/null || true

echo "== OpenSSL $OSSL_VER -> $PREFIX"
if [ ! -x "$PREFIX/bin/openssl" ] || ! "$PREFIX/bin/openssl" version | grep -q " 3\.5"; then
  mkdir -p "$HOME/opt/src" && cd "$HOME/opt/src"
  [ -f openssl-$OSSL_VER.tar.gz ] || curl -fL -o openssl-$OSSL_VER.tar.gz \
      https://github.com/openssl/openssl/releases/download/openssl-$OSSL_VER/openssl-$OSSL_VER.tar.gz
  sha256sum openssl-$OSSL_VER.tar.gz      # compare with the value published on the OpenSSL release page
  tar xzf openssl-$OSSL_VER.tar.gz && cd openssl-$OSSL_VER
  ./Configure --prefix="$PREFIX" --libdir=lib
  make -j"$(nproc)"
  make install_sw
  cd "$HERE"
fi
export LD_LIBRARY_PATH=$PREFIX/lib
"$PREFIX/bin/openssl" version
"$PREFIX/bin/openssl" list -kem-algorithms | grep -i mlkem | head -3
"$PREFIX/bin/openssl" list -signature-algorithms | grep -i -E "ml-dsa|mldsa" | head -3

cd "$HERE"
echo "== tls_probe"
gcc -O2 -Wall -o tls_probe tls_probe.c -I"$PREFIX/include" -L"$PREFIX/lib" -lssl -lcrypto -Wl,-rpath,"$PREFIX/lib"

echo "== certificates (real DER chains, depth 1-4; takes a few minutes, SLH-DSA is slow)"
# the repository holds the .pem files but NOT the private test keys (*.key are git-ignored): test the key
if [ ! -f ../certs/ML-DSA-65/d4/server.key ] || [ ! -f ../certs/ECDSA-P256/d4/server.key ]; then
  (cd "$HERE/.." && ./certs.sh)      # regenerates all keys and certificates (overwrites the committed .pem files)
else echo "already present"; fi
echo "setup done. Next: sudo ./host_tune.sh on; ./check_env.sh"
