# Description
![Alt text](idpasslite_qr.png?raw=true "api")

[![CircleCI](https://circleci.com/gh/newlogic42/lab_idpass_lite.svg?style=svg&circle-token=6df7dc471defbfdbb041013e6683f20dabccd8bb)](https://circleci.com/gh/newlogic42/lab_idpass_lite)

```
git clone --recurse-submodules ssh://git@github.com/newlogic42/lab_idpass_lite.git
```

## How to build `libidpasslite.so` only for your local machine

To build locally `libidpasslite.so`:

```
cd lab_idpass_lite/
mkdir build && cd build
cmake ..
cmake --build .
ls -l lib/idpass/libidpasslite.so
```

## How to build `libidpasslite.so` for Android architectures

This uses the Docker container having the required setup to build
the following Android architectures:

- armeabi-v7a
- arm64-v8a
- x86
- x86_64

```
docker run -it newlogic42/circleci-android bash
cd lab_idpass_lite/
./build.sh buildandroid
```

The Android outputs are in: `build/build.<arch>/` folder

## Opensource Dependencies

- https://github.com/jedisct1/libsodium.git
- https://github.com/davisking/dlib.git
- https://github.com/protocolbuffers/protobuf.git
- https://github.com/ricmoo/QRCode

