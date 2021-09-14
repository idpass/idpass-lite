#!/bin/sh
#

d=$(dirname $0)
cd $d

ABI=macosm1
INSTALL_PREFIX=$project/dependencies/build/$ABI

cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
    -DDLIB_PNG_SUPPORT=ON \
    -DDLIB_JPEG_SUPPORT=ON \
    -DDLIB_GIF_SUPPORT=OFF \
    -DDLIB_NO_GUI_SUPPORT=TRUE \
    -DDLIB_USE_BLAS=FALSE \
    -DDLIB_USE_LAPACK=FALSE \
    -DCMAKE_POSITION_INDEPENDENT_CODE=1 \
    -S $project/dependencies/src/dlib -B $tmpfolder/dlib/build.$ABI

cmake --build $tmpfolder/dlib/build.$ABI
make install
