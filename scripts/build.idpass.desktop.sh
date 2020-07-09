#!/bin/sh
#

d=$(dirname $0)
cd $d

ABI=desktop
INSTALL_PREFIX=$build/idpass/$ABI
mkdir -p $INSTALL_PREFIX
mkdir -p $build/idpass/build.$ABI
cd $build/idpass/build.$ABI

cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
    -DCMAKE_POSITION_INDEPENDENT_CODE=1 $project/lib/src 

cmake --build .
make install

cd $project
