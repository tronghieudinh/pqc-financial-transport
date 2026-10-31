#!/usr/bin/env bash
# Build liboqs 0.14.0 (Falcon is not in OpenSSL 3.5) into ~/opt/src/liboqs/build, as on the Arm machine.
# Run as a normal user; sudo only for apt.   ./build_liboqs.sh        (about 5-15 minutes on a laptop)
set -euo pipefail
VER=${OQS_VER:-0.14.0}
sudo apt-get install -y cmake ninja-build build-essential curl
mkdir -p "$HOME/opt/src" && cd "$HOME/opt/src"
if [ ! -d liboqs ]; then
  curl -fL -o liboqs-$VER.tar.gz https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$VER.tar.gz
  sha256sum liboqs-$VER.tar.gz          # compare with the value on the liboqs release page
  mkdir liboqs && tar xzf liboqs-$VER.tar.gz -C liboqs --strip-components=1
fi
cd liboqs
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release -DOQS_USE_OPENSSL=OFF -DBUILD_SHARED_LIBS=OFF
cmake --build build --parallel "$(nproc)"
ls -l build/tests/speed_sig && echo "liboqs $VER built"
