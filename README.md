# Description

The build process is executed inside a Docker container from the image `newlogic42/circleci-android:latest`:

```
git clone --recurse-submodules ssh://git@github.com/newlogic42/lab_idpassapi.git
cd lab_idpassapi/
./build.sh
```

The shared library libidpassapi.so` build output  will be under 
the `build/idpassapi/jniLibs/` folder. 


# Environment Variables Inside Container

The build scripts uses the following environment variables inside the container.

| Variable      | Value               |
| ------------- | ------------------- |
| HOME          | /home/circleci      |
| toolchain     | $HOME/toolchain     |
| project       | $HOME/project       |
| build         | $project/build      |
| libheaders    | $project/libheaders |
| API_LEVEL     | 29                  |

The default values of these environment variables are baked into the `Dockerfile`.
I override inside `build.sh` the `API_LEVEL` to a new value of `23`.

# libheaders

The project under `submodules` folder can be rebuilt for about an hour by:

```
rm -rf libheaders/*
rm -rf build/
./build.sh libheaders
```

Open another terminal, to see the progress:

```
$ tail -f build/build.log
Building dlib x86: done 229s
Building dlib x86_64: done 240s
Building dlib armeabi-v7a: done 191s
Building dlib arm64-v8a: done 226s
Building dlib desktop: done 190s
Building libsodium x86: done 86s
Building libsodium x86_64: done 88s
Building libsodium armeabi-v7a: done 78s
Building libsodium arm64-v8a: done 78s
Building libsodium desktop: done 102s
Building protobuf x86: done 406s
Building protobuf x86_64: done 401s
Building protobuf armeabi-v7a: done 402s
Building protobuf arm64-v8a: done 409s
Building protobuf desktop: done 357s
SUCCESS
```

These become the contents inside the `libheaders` folder. The applications under
the `apps` folder uses the header files and libraries inside `libheaders`.

# apps

The `idpassapi/` folder builds the `libidpassapi.so` shared library:
