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

    mkdir build && cd build
    cmake -DCOVERAGE=1 -DTESTAPP=1 ..
    cmake --build .
    #ctest -R create_card_verify_with_face
    ctest
}

buildandroid() {
	for abi in x86 x86_64 armeabi-v7a arm64-v8a;do
		echo "=========================================="
		echo "Building for Android architecture $abi ..."
		echo "=========================================="

		mkdir -p build/android.$abi && cd build/android.$abi

		cmake \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE \
		-DANDROID_NDK=$ANDROID_NDK_HOME \
		-DANDROID_TOOLCHAIN=clang \
		-DCMAKE_ANDROID_ARCH_ABI=$abi \
		-DANDROID_ABI=$abi \
		-DANDROID_LINKER_FLAGS="-landroid -llog" \
		-DANDROID_NATIVE_API_LEVEL=23 \
		-DANDROID_STL=c++_static \
		-DANDROID_CPP_FEATURES="rtti exceptions" ../..

		cmake --build .

		echo "*************************"
		echo "--- done Android $abi ---"
		echo "*************************"
		cd -
		sleep 3
	done
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

android)
buildandroid
;;

*)
build_desktop_idpasslite
;;
esac
