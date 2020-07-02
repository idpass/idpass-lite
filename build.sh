#!/bin/sh
#

API_LEVEL=23
p=/home/circleci/project

iscontainer() {
    cat /proc/1/cgroup | grep -w docker > /dev/null
    return $?
}

build_dependencies() {
    if iscontainer; then
        scripts/build.dependencies.sh
    else
        # get latest updates
        #docker pull newlogic42/circleci-android:latest
        docker run -it --user $(id -u):$(id -g) --rm -v `pwd`:/home/circleci/project -e API_LEVEL=23 newlogic42/circleci-android:latest /home/circleci/project/scripts/build.dependencies.sh
    fi
}

build_lib_idpasslite() {
    if iscontainer; then
        scripts/build.lib.idpass.sh
    else
        # get latest updates
        #docker pull newlogic42/circleci-android:latest
        docker run -it --user $(id -u):$(id -g) --rm -v `pwd`:/home/circleci/project -e API_LEVEL=23 newlogic42/circleci-android:latest /home/circleci/project/scripts/build.lib.idpass.sh
    fi
}

assert_exists() {
    type $1 2>/dev/null 1>&2 && return 
    echo "missing needed $1"
    exit 1
}

build_desktop_idpasslite() {
    # Check needed pre-requisites 
    assert_exists gcc 
    assert_exists g++
    assert_exists cmake
    assert_exists make
    # for #include <jni.h>
    assert_exists java 
    assert_exists javac 

    export project=`pwd`
    export build=$project/build
    mkdir -p build/
    cp scripts/build.idpass.desktop.sh build/
    build/build.idpass.desktop.sh
}

case "$1" in 
dependencies)
build_dependencies
;;

all)
build_dependencies
build_lib_idpasslite
;;

desktop)
build_desktop_idpasslite
;;

*)
build_lib_idpasslite
;;
esac
