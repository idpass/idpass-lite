#!/bin/sh
#

export tmpfolder=$(mktemp -d /tmp/idpasslitebuildir.XXX)
mkdir -p $tmpfolder && > $tmpfolder/build.log

dependencies=$project/dependencies

build_dlib() {
    # Dlib uses cmake so mkdir different folder for each platform build
    for x in $@; do
        mkdir -p $tmpfolder/dlib/build.$x
        cp $dependencies/scripts/build.dlib.$x.sh $tmpfolder/dlib/build.$x/
        chmod a+rx $tmpfolder/dlib/build.$x/build.dlib.$x.sh
    done

    for x in $@; do
        printf "Building dlib $x: " >> $tmpfolder/build.log
        t0=$(date +'%s')
        $tmpfolder/dlib/build.$x/build.dlib.$x.sh
        [ $? -ne 0 ] && exit 1
        t1=$(date +'%s')
        d=$((t1-t0))
        echo "done ${d}s" >> $tmpfolder/build.log
    done
}

build_libsodium() {
    # libsodium uses configure/make so the build of each platform is at root
    # folder and must clean at build start
    cp $dependencies/scripts/build.libsodium.*.sh $dependencies/src/libsodium/

    for x in $@; do
        printf "Building libsodium $x: " >> $tmpfolder/build.log
        t0=$(date +'%s')
        $dependencies/src/libsodium/build.libsodium.$x.sh
        [ $? -ne 0 ] && exit 1
        t1=$(date +'%s')
        d=$((t1-t0))
        echo "done ${d}s" >> $tmpfolder/build.log
    done
}

build_protobuf() {
    # libsodium uses configure/make so the build of each platform is at root
    # folder and must clean at build start
    cp $dependencies/scripts/build.protobuf.*.sh $dependencies/src/protobuf/

    for x in $@; do
        printf "Building protobuf $x: " >> $tmpfolder/build.log
        t0=$(date +'%s')
        $dependencies/src/protobuf/build.protobuf.$x.sh
        [ $? -ne 0 ] && exit 1
        t1=$(date +'%s')
        d=$((t1-t0))
        echo "done ${d}s" >> $tmpfolder/build.log
    done
}

build_dlib $@
build_libsodium $@
build_protobuf $@

echo "SUCCESS" >> $tmpfolder/build.log
rm -rf $tmpfolder
