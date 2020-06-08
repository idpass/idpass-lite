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
    -S $project/lib/tests -B $build/idpassapitests/build.$ABI


cmake --build $build/idpassapitests/build.$ABI
#make install
cp -a $project/lib/tests/data .
./idpassapitests

if [ $? -eq 0 ];then
    tar cvpf $build/idpassapi/jniLibs.tar $build/idpassapi/jniLibs/
fi

cd $project
