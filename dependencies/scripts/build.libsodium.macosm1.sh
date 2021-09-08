#!/bin/sh
#

export ABI=macosm1
export INSTALL_PREFIX=$project/dependencies/build/$ABI

export LIBSODIUM_ENABLE_MINIMAL_FLAG="--enable-minimal"
export MACOS_ARM64_PREFIX="${INSTALL_PREFIX}"
export MACOS_VERSION_MIN=10.10
export CFLAGS="-O2 -arch arm64 -mmacosx-version-min=${MACOS_VERSION_MIN}"
export LDFLAGS="-arch arm64 -mmacosx-version-min=${MACOS_VERSION_MIN}"

d=$(dirname $0)
cd $d

[ ! -e configure ] && ./autogen.sh

make clean
make distclean

./configure \
    --host=arm-apple-darwin20 \
    --disable-shared \
    --prefix="$INSTALL_PREFIX" \
    ${LIBSODIUM_ENABLE_MINIMAL_FLAG}

make
make install
