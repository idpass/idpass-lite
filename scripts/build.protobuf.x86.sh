#!/bin/sh
#

export ABI=x86
export TOOLCHAIN=$toolchain/$platform.$ABI
export INSTALL_PREFIX=$libheaders/$ABI
export SYSROOT=$TOOLCHAIN/sysroot
export PATH=$TOOLCHAIN/bin:$PATH
export CC="i686-linux-android-clang --sysroot $SYSROOT"
export CXX="i686-linux-android-clang++ --sysroot $SYSROOT"

d=$(dirname $0)
cd $d

[ ! -e configure ] && ./autogen.sh

make clean
make distclean

./configure \
    --host=i686-linux-android \
    --with-protoc=protoc \
    --with-sysroot="$SYSROOT" \
    --disable-shared \
    --prefix="$INSTALL_PREFIX" \
    --enable-cross-compile \
    CFLAGS="-fPIC -march=i686 -D__ANDROID_API__=$API_LEVEL" \
    CXXFLAGS="-fPIC -frtti -fexceptions -march=i686 -D__ANDROID_API__=$API_LEVEL" \
    LIBS="-llog -lz -lc++_static"

make 

if [ $? -ne 0 ];then
    echo "**************************"
    echo "*** correcting script ***"
    echo "**************************"
    sleep 10
    $TOOLCHAIN/bin/i686-linux-android-ranlib src/.libs/libprotobuf.a
    $TOOLCHAIN/bin/i686-linux-android-ranlib src/.libs/libprotoc.a
    make 
fi

make install

cd -
