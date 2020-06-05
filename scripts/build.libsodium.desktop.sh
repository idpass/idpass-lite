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
    --disable-shared \
    --with-pic="yes" \
    --prefix="$INSTALL_PREFIX"

make
make install

cd -
