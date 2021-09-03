#!/bin/sh
#

export ABI=macosm1
export INSTALL_PREFIX=$project/dependencies/build/$ABI

d=$(dirname $0)
cd $d

[ ! -e configure ] && ./autogen.sh

make clean
make distclean

export CFLAGS="-Os"

./configure \
    --host=arm-none-eabi \
    --disable-shared \
    --with-pic="yes" \
    --prefix="$INSTALL_PREFIX"

make
make install
