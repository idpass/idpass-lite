# Prebuilt headers and libraries

First, make sure that the submodules source codes are there:

```
git submodule update
```

The needed prebuilt headers and libraries are under the build/ folder for each architecture.
These are provided as prebuilt but they can be rebuilt from their sources under src/ folder
by:

```
cd idpass-lite
rm -rf dependencies/build/
./build.sh dependencies
```

It takes about 50 minutes to rebuild the build/ folder from source. To see it's current
progress, open another terminal and `tail`:

```
cd idpass-lite/
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

# Windows Build Steps

This needs a Microsoft Visual Studio compiler. The free community edition works
for example I use the Microsoft Visual Studio 2019 IDE. All prebuilt can be build
via command line DOS in Windows. You also need to have `cmake` installed for
Windows. You also need handy the `git bash` shell for Windows. Do not use `cygwin`.

## Building Dlib

Same as in Linux it uses cmake. Open git bash shell or DOS cmd:

```
cd dependencies/src/dlib
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=install -T host=x64 ..
cmake --build . --config Release --target INSTALL
```

Result is a fully ready header files and lib under install folder.

## Building Protobuf

In Linux the build system uses configure but in Windows system it uses cmake. 
Open git bash shell:

```
cd dependencies/src/protobuf
cd cmake
mkdir -p build/release && cd build/release
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../install ../..
cmake --build . --config Release --target INSTALL
```

Result is fully ready header files, lib, and protoc.exe under the install folder.


## Building Libsodium

This the most different to build under Windows. It does not use cmake nor any other 
Unix way of building things. Open any DOS shell.

Edit buildall.bat and comment out non-existent Visual Studio versions. For example, 
I have Visual Studio 2019 therefore I keep this line and comment out the other lines.

```
cd dependencies/src/libsodium
cd builds\msvc\build
buildall.bat
```

Result is dynamic and static libraries under libsodium/bin folder. 

Proceed to create a Visual Studio project is created for `idpasslite.dll` which 
references the header files and static libraries that got in the above steps. 
