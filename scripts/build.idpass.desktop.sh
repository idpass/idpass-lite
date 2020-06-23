#!/bin/sh
#

d=$(dirname $0)
cd $d

ABI=desktop
INSTALL_PREFIX=$build/idpass/$ABI

cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
    -DCMAKE_POSITION_INDEPENDENT_CODE=1 \
    -S $project/lib/src -B $build/idpass/build.$ABI

cmake --build $build/idpass/build.$ABI
make install

cd $project
