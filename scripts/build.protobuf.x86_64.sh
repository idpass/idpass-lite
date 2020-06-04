#!/bin/sh
#

export ABI=x86_64
export TOOLCHAIN=$toolchain/$platform.$ABI
export INSTALL_PREFIX=$libheaders/$ABI
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
    --with-protoc=protoc \
    --with-sysroot="$SYSROOT" \
    --disable-shared \
    --prefix="$INSTALL_PREFIX" \
    --enable-cross-compile \
    CFLAGS="-fPIC -march=x86-64 -D__ANDROID_API__=$API_LEVEL" \
    CXXFLAGS="-fPIC -frtti -fexceptions -march=x86-64 -D__ANDROID_API__=$API_LEVEL" \
    LIBS="-llog -lz -lc++_static"

make

if [ $? -ne 0 ];then
    echo "**************************"
    echo "*** correcting script ***"
    echo "**************************"
    sleep 10
    $TOOLCHAIN/bin/x86_64-linux-android-ranlib src/.libs/libprotobuf.a
    $TOOLCHAIN/bin/x86_64-linux-android-ranlib src/.libs/libprotoc.a
    make
fi

make install

cd -
