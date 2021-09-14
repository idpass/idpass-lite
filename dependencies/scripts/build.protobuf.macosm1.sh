#!/bin/sh
#

export ABI=macosm1
export INSTALL_PREFIX=$project/dependencies/build/$ABI

d=$(dirname $0)
cd $d

[ ! -e configure ] && ./autogen.sh

make clean
make distclean

./configure \
    --host=arm-none-eabi \
    --with-protoc=protoc \
    --disable-shared \
    --prefix="$INSTALL_PREFIX" \
    CXXFLAGS="-fPIC -frtti -fexceptions" \
    LIBS="-lz"

make 
make install
