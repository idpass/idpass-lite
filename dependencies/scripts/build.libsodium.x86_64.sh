#!/bin/sh
#

export ABI=x86_64
export INSTALL_PREFIX=$dependencies/build/$ABI
export TOOLCHAIN=$toolchain/$platform.$ABI
export SYSROOT=$TOOLCHAIN/sysroot
export PATH=$TOOLCHAIN/bin:$PATH
export CC="x86_64-linux-android-clang --sysroot $SYSROOT"
export CXX="x86_64-linux-android-clang++ --sysroot $SYSROOT"

d=$(dirname $0)
cd $d

[ ! -e configure ] && ./autogen.sh

make clean
make distclean

./configure \
    --host=x86_64-linux-android \
    --with-sysroot="$SYSROOT" \
    --disable-shared \
    --with-pic="yes" \
    CFLAGS="-march=x86-64 -D__ANDROID_API__=$API_LEVEL" \
    --prefix="$INSTALL_PREFIX"

make
make install
