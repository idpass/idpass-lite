#!/bin/sh
#

d=$(dirname $0)
cd $d

ABI=x86_64
INSTALL_PREFIX=$build/idpassapi/jniLibs/$ABI

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
    -S $project/apps/idpassapi/ -B $build/idpassapi/build.$ABI

cmake --build $build/idpassapi/build.$ABI
make install

cd $project
