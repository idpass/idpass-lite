#!/bin/sh
#

d=$(dirname $0)
cd $d

ABI=desktop
INSTALL_PREFIX=$build/idpasstests/$ABI
mkdir -p $INSTALL_PREFIX
mkdir -p $build/idpasstests/build.$ABI
cd $build/idpasstests/build.$ABI

cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
    -DCMAKE_POSITION_INDEPENDENT_CODE=1 \
    $project/lib/tests 

cmake --build .
#cmake --build $build/idpasstests/build.$ABI
#make install
#cp -a $project/lib/tests/data .

./idpasstests

if [ $? -eq 0 ];then
    if [ -d $build/idpass/jniLibs/ ];then
        # Produce a CircleCI downloadable artifact
        tar cvjpf $build/idpass/jniLibs.tar.bz2 $build/idpass/jniLibs/
        md5sum $build/idpass/jniLibs.tar.bz2 > $build/idpass/jniLibs.tar.bz2.md5sum
    fi
fi

cd $project
