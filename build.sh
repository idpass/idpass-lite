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
        docker run -it --user $(id -u):$(id -g) --rm \
            -v `pwd`:/home/circleci/project \
            -e API_LEVEL=23  \
            newlogic42/circleci-android:latest \
            /home/circleci/project/scripts/build.dependencies.sh
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

build_debug() {
    echo "***********************************"
    echo "Building debug libidpasslite.so ..."
    echo "***********************************"
    sleep 3
    rm -rf build/debug
    mkdir -p build/debug && cd build/debug
    cmake -DCOVERAGE=1 -DTESTAPP=1 -DCMAKE_POSITION_INDEPENDENT_CODE=1 ../..
    cmake --build .
    ctest
    cd -
    ls -l build/debug/lib/src/libidpasslite.so
    md5sum build/release/lib/src/libidpasslite.so > build/release/lib/src/libidpasslite.so.md5sum

    # Generate test coverage report
    lcov -c --directory build/debug/lib/src/CMakeFiles/idpasslite.dir --output-file build/cov.info
    lcov --extract build/cov.info "/home/circleci/project/lib/*" -o build/cov_idpass.info
    genhtml build/cov_idpass.info -o build/html/
    tar cvpf build/html.tar build/html

    mkdir -p build/test_results/demangle/
    mkdir build/test_results/nomangle/

    python /home/circleci/bin/lcov_cobertura.py \
        build/cov_idpass.info \
        --base-dir build/debug/lib/src/CMakeFiles/idpasslite.dir \
        --output build/test_results/demangle/results.xml \
        --demangle

    python3 /home/circleci/bin/lcov_cobertura.py \
        build/cov_idpass.info \
        --base-dir build/debug/lib/src/CMakeFiles/idpasslite.dir \
        --output build/test_results/nomangle/results.xml

}

build_release() {
    echo "*************************************"
    echo "Building release libidpasslite.so ..."
    echo "*************************************"
    sleep 3
    rm -rf build/release
    mkdir -p build/release && cd build/release
    cmake -DCMAKE_BUILD_TYPE=Release -DTESTAPP=1 -DCMAKE_POSITION_INDEPENDENT_CODE=1 ../..
    cmake --build .
    ctest
    echo
    cd -
    ls -l build/release/lib/src/libidpasslite.so
}

###########################################################
# The build_desktop_idpasslite function directly does the 
# cmake build without using a container
###########################################################
build_desktop_idpasslite() {
    # Check needed pre-requisites 
    assert_exists gcc 
    assert_exists g++
    assert_exists cmake
    assert_exists make
    # for #include <jni.h>
    assert_exists java 
    assert_exists javac 

    build_release
}

build_inside_container() {
    if iscontainer; then
        case "$1" in
        debug)
        build_debug  
        ;;
        release)
        build_release
        ;;
        android)
        build_android $2
        ;;
        *)
        build_debug && build_release
        esac
    else
        ####################
        # get latest updates
        #docker pull newlogic42/circleci-android:latest

        docker run -it --user $(id -u):$(id -g) --rm \
            -v `pwd`:/home/circleci/project \
            -e API_LEVEL=23 \
            -w /home/circleci/project/ \
            newlogic42/circleci-android:latest \
            /home/circleci/project/build.sh $@
    fi
}

build_android() {
    local abi
    if [ $# -eq 0 ]; then
        echo "*** Building all supported Android architectures ***"
        sleep 3
        for abi in x86 x86_64 armeabi-v7a arm64-v8a;do
            echo "=========================================="
            echo "Building for Android architecture $abi ..."
            echo "=========================================="

            local builddir=build/android.$abi
            rm -rf $builddir
            mkdir -p $builddir && cd $builddir

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

            echo "***********************************"
            echo "--- Done building Android $abi ---"
            echo "***********************************"
            cd -
            sleep 3
        done
    else
        case "$1" in
        x86|x86_64|armeabi-v7a|arm64-v8a)
        echo "*** Building Android architectures $1 ***"
        sleep 3
        abi=$1    
        local builddir=build/android.$abi
        rm -rf $builddir
        mkdir -p $builddir && cd $builddir

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

        echo "***********************************"
        echo "--- Done building Android $abi ---"
        echo "***********************************"
        cd -
        ;;

        *)
        echo "Unknown android arch $1"
        esac
    fi
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
build_inside_container $@
;;

debug)
build_inside_container debug
;;

release)
build_inside_container release
;;

*)
build_inside_container
;;
esac
