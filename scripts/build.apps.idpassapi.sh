#!/bin/sh
#

for x in x86 x86_64 armeabi-v7a arm64-v8a desktop;do
    mkdir -p $build/idpassapi/build.$x
    cp $project/scripts/build.idpassapi.$x.sh $build/idpassapi/build.$x
done

echo "*** Compiling libidpassapi.so ***"
sleep 3

for x in x86 x86_64 armeabi-v7a arm64-v8a desktop;do
    $build/idpassapi/build.$x/build.idpassapi.$x.sh
    cd $project
done

echo "*** Compiling idpassapitests ***"
sleep 5

# Run C++ test client
cd $project
mkdir -p $build/idpassapitests/build.desktop/
cp $project/scripts/build.idpassapitests.desktop.sh $build/idpassapitests/build.desktop/
cd $build/idpassapitests/build.desktop/
./build.idpassapitests.desktop.sh

## Run Java JNI test client
cd $project
cd apps/javatests/
./run.sh
