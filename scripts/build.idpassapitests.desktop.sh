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
    tar cvjpf $build/idpassapi/jniLibs.tar.bz2 $build/idpassapi/jniLibs/
    md5sum $build/idpassapi/jniLibs.tar.bz2 > $build/idpassapi/jniLibs.tar.bz2.md5sum
fi

cd $project
