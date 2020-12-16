# ID PASS Lite

[![CircleCI](https://circleci.com/gh/idpass/idpass-lite.svg?style=svg)](https://circleci.com/gh/idpass/idpass-lite)

![Alt text](idpasslite_qr.png?raw=true "api")


```
git clone --recurse-submodules https://github.com/idpass/idpass-lite.git
```

## How to build `libidpasslite.so` 

`./build.sh` to build the debug and release versions
and the generated `lcov` coverage reports written to `build/html/` folder. 

Or you can do a specific build by:

```
cd idpass-lite/
./build.sh desktop 
./build.sh debug   
./build.sh release
./build.sh android
./build.sh android arm64-v8a
./build.sh android arm32-v7a
./build.sh android x86_64
```

All of the above builds, (except `build.sh desktop`), uses a Docker 
container to do the build.

You maybe be able to use your local machine to do these Android builds 
if you can supply the value of the variables below. For example, to 
build for `arm64-v8a` Android platform:

```
TOOLCHAIN_FILE=/opt/android/android-ndk-r20/build/cmake/android.toolchain.cmake
ANDROID_NDK_HOME=/opt/android/android-ndk-r20
abi=arm64-v8a

mkdir arm64-v8a.build
cd arm64-v8a.build
            cmake \
                -DCMAKE_BUILD_TYPE=Release \
                -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE \
                -DANDROID_NDK=$ANDROID_NDK_HOME \
                -DANDROID_TOOLCHAIN=clang \
                -DCMAKE_ANDROID_ARCH_ABI=$abi \
                -DANDROID_ABI=$abi \
                -DANDROID_LINKER_FLAGS="-landroid -llog" \
                -DANDROID_NATIVE_API_LEVEL=23 \
                -DANDROID_STL=c++_static \
                -DANDROID_CPP_FEATURES="rtti exceptions" ../..
```

## Opensource Dependencies

- https://github.com/jedisct1/libsodium.git
- https://github.com/davisking/dlib.git
- https://github.com/protocolbuffers/protobuf.git
- https://github.com/ricmoo/QRCode

