#!/bin/sh
#

export ABI=armeabi-v7a
export TOOLCHAIN=$toolchain/$platform.$ABI
export INSTALL_PREFIX=$dependencies/build/$ABI
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
    --with-protoc=protoc \
    --with-sysroot="$SYSROOT" \
    --disable-shared \
    --prefix="$INSTALL_PREFIX" \
    --enable-cross-compile \
    CFLAGS="-fPIC -march=armv7-a -D__ANDROID_API__=$API_LEVEL" \
    CXXFLAGS="-fPIC -frtti -fexceptions -march=armv7-a -D__ANDROID_API__=$API_LEVEL" \
    LIBS="-llog -lz -lc++_static"

make

if [ $? -ne 0 ];then
    echo "**************************"
    echo "*** correcting script ***"
    echo "**************************"
    sleep 5
    $TOOLCHAIN/bin/arm-linux-androideabi-ranlib src/.libs/libprotobuf.a
    $TOOLCHAIN/bin/arm-linux-androideabi-ranlib src/.libs/libprotoc.a
    make
fi

make install

cd -
