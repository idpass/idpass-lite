#!/bin/sh
#

export ABI=arm64-v8a
export TOOLCHAIN=$toolchain/$platform.$ABI
export INSTALL_PREFIX=$dependencies/build/$ABI
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
    --with-protoc=protoc \
    --with-sysroot="$SYSROOT" \
    --disable-shared \
    --prefix="$INSTALL_PREFIX" \
    --enable-cross-compile \
    CFLAGS="-fPIC -march=armv8-a -D__ANDROID_API__=$API_LEVEL" \
    CXXFLAGS="-fPIC -frtti -fexceptions -march=armv8-a -D__ANDROID_API__=$API_LEVEL" \
    LIBS="-llog -lz -lc++_static"

make 

if [ $? -ne 0 ];then
    echo "*************************"
    echo "*** correcting script ***"
    echo "*************************"
    sleep 10
    $TOOLCHAIN/bin/aarch64-linux-android-ranlib src/.libs/libprotobuf.a
    $TOOLCHAIN/bin/aarch64-linux-android-ranlib src/.libs/libprotoc.a
    make 
fi

make install
$TOOLCHAIN/bin/aarch64-linux-android-ranlib $INSTALL_PREFIX/lib/libprotobuf.a

cd -
