#!/bin/sh
#

export ABI=x86
export INSTALL_PREFIX=$libheaders/$ABI
export TOOLCHAIN=$toolchain/$platform.$ABI
export SYSROOT=$TOOLCHAIN/sysroot/
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
    --disable-shared \
    --with-sysroot="$SYSROOT" \
    --with-pic="yes" \
    CFLAGS="-march=i686 -D__ANDROID_API__=$API_LEVEL" \
    --prefix="$INSTALL_PREFIX"

make 
make install

cd -
