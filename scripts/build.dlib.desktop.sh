#!/bin/sh
#

d=$(dirname $0)
cd $d

ABI=desktop
INSTALL_PREFIX=$libheaders/$ABI

cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
    -DDLIB_PNG_SUPPORT=ON \
    -DDLIB_JPEG_SUPPORT=ON \
    -DDLIB_NO_GUI_SUPPORT=TRUE \
    -DDLIB_USE_BLAS=FALSE \
    -DDLIB_USE_LAPACK=FALSE \
    -DCMAKE_POSITION_INDEPENDENT_CODE=1 \
    -S $project/submodules/dlib -B $build/dlib/build.$ABI

cmake --build $build/dlib/build.$ABI
make install

cd $project
