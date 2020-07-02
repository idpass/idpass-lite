# Prebuilt headers and libraries

The needed prebuilt headers and libraries are under the build/ folder for each architecture.
These are provided as prebuilt but they can be rebuilt from their sources under src/ folder
by:

```
cd lab_idpassapi
rm -rf dependencies/build/
./build.sh dependencies
```

It takes about 50 minutes to rebuild the build/ folder from source. To see it's current
progress, open another terminal and `tail`:

```
cd lab_idpassapi/
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

