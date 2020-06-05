#!/bin/sh
#

export ABI=desktop
export INSTALL_PREFIX=$dependencies/build/$ABI

d=$(dirname $0)
cd $d

[ ! -e configure ] && ./autogen.sh

make clean
make distclean

./configure \
    --with-protoc=protoc \
    --disable-shared \
    --prefix="$INSTALL_PREFIX" \
    CXXFLAGS="-fPIC -frtti -fexceptions" \
    LIBS="-lz"

make 
make install

cd -
