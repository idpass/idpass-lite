#!/bin/sh
#

d=$(dirname $0)
cd $d

ABI=arm64-v8a
INSTALL_PREFIX=$build/idpass/jniLibs/$ABI

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
    -DANDROID_CPP_FEATURES="rtti exceptions" \
    -S $project/lib/src/ -B $build/idpass/build.$ABI

cmake --build $build/idpass/build.$ABI/
make install

cd $project
