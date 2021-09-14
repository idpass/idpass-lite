#!/bin/sh
#

export ABI=armeabi-v7a
export INSTALL_PREFIX=$dependencies/build/$ABI
export TOOLCHAIN=$toolchain/$platform.$ABI
export SYSROOT=$TOOLCHAIN/sysroot
export PATH=$TOOLCHAIN/bin:$PATH
export CC="arm-linux-androideabi-clang --sysroot $SYSROOT"
export CXX="arm-linux-androideabi-clang++ --sysroot $SYSROOT"

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
    CFLAGS="-march=armv7-a -D__ANDROID_API__=$API_LEVEL" \
    --prefix="$INSTALL_PREFIX"

make
make install
