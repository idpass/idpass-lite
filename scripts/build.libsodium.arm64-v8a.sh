#!/bin/sh
#

export ABI=arm64-v8a
export INSTALL_PREFIX=$libheaders/$ABI
export TOOLCHAIN=$toolchain/$platform.$ABI
export SYSROOT=$TOOLCHAIN/sysroot
export PATH=$TOOLCHAIN/bin:$PATH
export CC="aarch64-linux-android-clang --sysroot $SYSROOT"
export CXX="aarch64-linux-android-clang++ --sysroot $SYSROOT"

d=$(dirname $0)
cd $d

[ ! -e configure ] && ./autogen.sh

make clean
make distclean

./configure \
    --host=arm-linux-androideabi \
    --with-sysroot="$SYSROOT" \
    --disable-shared \
    --with-pic="yes" \
    CFLAGS="-march=armv8-a -D__ANDROID_API__=$API_LEVEL" \
    --prefix="$INSTALL_PREFIX"

make
make install
$TOOLCHAIN/bin/aarch64-linux-android-ranlib $INSTALL_PREFIX/lib/libsodium.a

cd -
