#!/bin/sh
#

for x in x86 x86_64 armeabi-v7a arm64-v8a desktop;do
    mkdir -p $build/idpass/build.$x
    cp $project/scripts/build.idpass.$x.sh $build/idpass/build.$x
done

echo "*** Compiling libidpass.so ***"
sleep 3

for x in x86 x86_64 armeabi-v7a arm64-v8a desktop;do
    $build/idpass/build.$x/build.idpass.$x.sh
    cd $project
done

echo "*** Compiling idpasstests ***"
sleep 5

# Run C++ test client
cd $project
mkdir -p $build/idpasstests/build.desktop/
cp $project/scripts/build.idpasstests.desktop.sh $build/idpasstests/build.desktop/
cd $build/idpasstests/build.desktop/
./build.idpasstests.desktop.sh
