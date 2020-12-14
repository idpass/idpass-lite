# ID PASS Lite

[![CircleCI](https://circleci.com/gh/idpass/idpass-lite.svg?style=svg&circle-token=937634c8f42536396097ea8c04097035b9c9a509)](https://circleci.com/gh/idpass/idpass-lite)

A library to create and issue biometrically-binding QR code identity cards.

![Alt text](idpasslite_qr.png?raw=true "api")

## Usage

This library can be used in C and C++ projects.

## Building from source

To use the latest version of this library, we can build it from source.

**Clone the repository**

```bash
git clone --recurse-submodules ssh://git@github.com/idpass/idpass-lite.git
```

Be sure to have the following build tools installed before proceeding: [cmake](https://cmake.org/install/), [protobuf](https://grpc.io/docs/protoc-installation/)

**Debug and release builds**

```bash
./build.sh
```

This generates the debug and release builds for `x86-64` platform inside the `build` directory. `libidpasslite.so` can be found in `build/{debug,release}/lib/src/libidpasslite.so`. We can copy this file into our project to start using it.

Additionally, coverage reports for the build are written in the `build/html` directory.

**Specific builds**

It's also possible to generate specific builds by passing the desired build as arguments to `build.sh`.

```bash
./build.sh desktop
./build.sh debug
./build.sh release
./build.sh android
./build.sh android arm64-v8a
./build.sh android arm32-v7a
./build.sh android x86_64
./build.sh android x86
```

All the builds (except for `desktop`) are done inside a container, so we would need to install [Docker](https://docs.docker.com/get-docker/). It might be possible to use our local machine for the Android builds if we can supply these environment variables:

```bash
TOOLCHAIN_FILE=/opt/android/android-ndk-r20/build/cmake/android.toolchain.cmake
ANDROID_NDK_HOME=/opt/android/android-ndk-r20
```

## Open source dependencies

- [libsodium](https://github.com/jedisct1/libsodium.git)
- [dlib](https://github.com/davisking/dlib.git)
- [protobuf](https://github.com/protocolbuffers/protobuf.git)
- [QRCode](https://github.com/ricmoo/QRCode)

## License

[Apache-2.0 License](LICENSE)
