#!/bin/sh
#

d=$(dirname $0)
cd $d

ABI=desktop
INSTALL_PREFIX=$build/idpasstests/$ABI

cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
    -DCMAKE_POSITION_INDEPENDENT_CODE=1 \
    -S $project/lib/tests -B $build/idpasstests/build.$ABI


cmake --build $build/idpasstests/build.$ABI
#make install
cp -a $project/lib/tests/data .
./idpasstests

if [ $? -eq 0 ];then
    tar cvjpf $build/idpass/jniLibs.tar.bz2 $build/idpass/jniLibs/
    md5sum $build/idpass/jniLibs.tar.bz2 > $build/idpass/jniLibs.tar.bz2.md5sum
fi

cd $project
