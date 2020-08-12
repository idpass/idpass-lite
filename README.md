# ID PASS Lite

[![CircleCI](https://circleci.com/gh/idpass/idpass-lite.svg?style=svg)](https://circleci.com/gh/idpass/idpass-lite)

![Alt text](idpasslite_qr.png?raw=true "api")


```
git clone --recurse-submodules ssh://git@github.com/newlogic42/lab_idpass_lite.git
```

## How to build `libidpasslite.so` 

You can simply type `./build.sh` and it will build the debug and release versions
and the generated `lcov` coverage reports written to `build/html/` folder. 

Or you can do a specific build by:

```
cd lab_idpass_lite/
./build.sh desktop 
./build.sh debug   
./build.sh release
./build.sh android
./build.sh android arm64-v8a
./build.sh android arm32-v7a
./build.sh android x86_64
```

The Android build types are done inside a container. You maybe be able to use your
local machine to do these Android builds if you can supply the value of the
variables below:

- $TOOLCHAIN_FILE   = /opt/android/android-ndk-r20/build/cmake/android.toolchain.cmake
- $ANDROID_NDK_HOME = /opt/android/android-ndk-r20

## Opensource Dependencies

- https://github.com/jedisct1/libsodium.git
- https://github.com/davisking/dlib.git
- https://github.com/protocolbuffers/protobuf.git
- https://github.com/ricmoo/QRCode

