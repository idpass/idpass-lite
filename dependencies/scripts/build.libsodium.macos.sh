#!/bin/sh
#

export ABI=macos
export INSTALL_PREFIX=$project/dependencies/build/$ABI

d=$(dirname $0)
cd $d

[ ! -e configure ] && ./autogen.sh

make clean
make distclean

./configure \
    --disable-shared \
    --with-pic="yes" \
    --prefix="$INSTALL_PREFIX"

make
make install
