#!/bin/sh
#

> $build/build.log

build_dlib() {
    for x in x86 x86_64 armeabi-v7a arm64-v8a desktop; do
        mkdir -p $build/dlib/build.$x
        cp $project/scripts/build.dlib.$x.sh $build/dlib/build.$x/
        chmod a+rx $build/dlib/build.$x/build.dlib.$x.sh
    done

    for x in x86 x86_64 armeabi-v7a arm64-v8a desktop; do
        printf "Building dlib $x: " >> $build/build.log
        t0=$(date +'%s')
        $build/dlib/build.$x/build.dlib.$x.sh
        [ $? -ne 0 ] && exit 1
        t1=$(date +'%s')
        d=$((t1-t0))
        echo "done ${d}s" >> $build/build.log
    done
}

build_libsodium() {
    cp $project/scripts/build.libsodium.*.sh $project/submodules/libsodium/

    for x in x86 x86_64 armeabi-v7a arm64-v8a desktop; do
        printf "Building libsodium $x: " >> $build/build.log
        t0=$(date +'%s')
        $project/submodules/libsodium/build.libsodium.$x.sh
        [ $? -ne 0 ] && exit 1
        t1=$(date +'%s')
        d=$((t1-t0))
        echo "done ${d}s" >> $build/build.log
    done
}

build_protobuf() {
    cp $project/scripts/build.protobuf.*.sh $project/submodules/protobuf/

    for x in x86 x86_64 armeabi-v7a arm64-v8a desktop; do
        printf "Building protobuf $x: " >> $build/build.log
        t0=$(date +'%s')
        $project/submodules/protobuf/build.protobuf.$x.sh
        [ $? -ne 0 ] && exit 1
        t1=$(date +'%s')
        d=$((t1-t0))
        echo "done ${d}s" >> $build/build.log
    done
}

build_dlib
build_libsodium
build_protobuf

echo "SUCCESS" >> $build/build.log
