#!/bin/sh
#

export ABI=arm64-v8a
export TOOLCHAIN=$toolchain/$platform.$ABI
export INSTALL_PREFIX=$dependencies/build/$ABI
export SYSROOT=$TOOLCHAIN/sysroot
export PATH=$TOOLCHAIN/bin:$PATH
export CC="aarch64-linux-android-clang --sysroot $SYSROOT"
export CXX="aarch64-linux-android-clang++ --sysroot $SYSROOT"
export RANLIB=$TOOLCHAIN/bin/aarch64-linux-android-ranlib

d=$(dirname $0)
cd $d

[ ! -e configure ] && ./autogen.sh

make clean
make distclean

./configure \
    --host=arm-linux-androideabi \
    --with-protoc=protoc \
    --with-sysroot="$SYSROOT" \
    --disable-shared \
    --prefix="$INSTALL_PREFIX" \
    --enable-cross-compile \
    CFLAGS="-fPIC -march=armv8-a -D__ANDROID_API__=$API_LEVEL" \
    CXXFLAGS="-fPIC -frtti -fexceptions -march=armv8-a -D__ANDROID_API__=$API_LEVEL" \
    LIBS="-llog -lz -lc++_static"

make 
make install
