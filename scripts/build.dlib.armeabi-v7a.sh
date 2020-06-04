#!/bin/sh
#

d=$(dirname $0)
cd $d

ABI=armeabi-v7a
INSTALL_PREFIX=$libheaders/$ABI

cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
    -DANDROID_NDK=$ANDROID_NDK_HOME \
    -DANDROID_TOOLCHAIN=clang \
    -DCMAKE_ANDROID_ARCH_ABI=$ABI \
    -DANDROID_ABI=$ABI \
    -DANDROID_LINKER_FLAGS="-landroid -llog" \
    -DANDROID_NATIVE_API_LEVEL=$API_LEVEL \
    -DANDROID_STL=c++_static \
    -DDLIB_PNG_SUPPORT=ON \
    -DDLIB_JPEG_SUPPORT=ON \
    -DDLIB_NO_GUI_SUPPORT=TRUE \
    -DDLIB_USE_BLAS=FALSE \
    -DDLIB_USE_LAPACK=FALSE \
    -DANDROID_CPP_FEATURES="rtti exceptions" \
    -S $project/submodules/dlib -B $build/dlib/build.$ABI

cmake --build $build/dlib/build.$ABI
make install

cd $project
