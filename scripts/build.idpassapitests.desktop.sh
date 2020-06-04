#!/bin/sh
#

d=$(dirname $0)
cd $d

ABI=desktop
INSTALL_PREFIX=$build/idpassapitests/$ABI

cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
    -DCMAKE_POSITION_INDEPENDENT_CODE=1 \
    -S $project/apps/idpassapitests -B $build/idpassapitests/build.$ABI


cmake --build $build/idpassapitests/build.$ABI
#make install
cp -a $project/apps/idpassapitests/data .
./idpassapitests

cd $project
