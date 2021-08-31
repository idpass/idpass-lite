#!/bin/sh
#

project=$(pwd)
export GTEST_OUTPUT="xml:$(pwd)/build/reports.xml"
export IDPASSLITE=$project/build/debug/lib/src/libidpasslite.so
export CLASSPATH=$project/build/debug/lib/tests/jni/
export FACERECOGNITIONDATA=$project/lib/src/models/dlib_face_recognition_resnet_model_v1.dat
export SHAPEPREDICTIONDATA=$project/lib/src/models/shape_predictor_5_face_landmarks.dat
API_LEVEL=23

iscontainer() {
    cat /proc/1/cgroup | grep -w docker > /dev/null
    return $?
}

build_dependencies() {
    if [ $2 = "macos" ];then
        shift
        $project/dependencies/rebuild.sh $@
    else
    if iscontainer; then
        shift
        $project/dependencies/rebuild.sh $@
    else
        # get latest updates
        docker pull typelogic/circleci-android:latest
        docker run -it --user $(id -u):$(id -g) --rm \
            -v `pwd`:/home/circleci/project/ \
            -e API_LEVEL=23  \
            -w /home/circleci/project/ \
            typelogic/circleci-android:latest \
            /home/circleci/project/build.sh $@
    fi
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
    #rm -rf build/debug
    mkdir -p build/debug && cd build/debug
    cmake -DCOVERAGE=1 -DTESTAPP=1 -DCMAKE_POSITION_INDEPENDENT_CODE=1 -DALWAYS=1 -DEMBED_MODELS=1 ../..
    cmake --build .
    [ $? -ne 0 ] && return 1
    cd - >/dev/null
	
    echo "**************************************"
    echo "Executing test cases for code coverage"
    echo "**************************************"
    build/debug/lib/tests/idpasstests build/debug/lib/tests/data/
    if [ $? -ne 0 ];then
        return 1
    fi

    ls -lh build/debug/lib/src/libidpasslite.so
    javac $project/build/debug/lib/tests/jni/org/idpass/lite/IDPassReader.java
    # test JNI methods link to libidpasslite.so
    java org.idpass.lite.IDPassReader || return 1

    echo
    echo "****************************"
    echo "Gathering code coverage data"
    echo "****************************"
    lcov -c --directory build/debug/lib/src/CMakeFiles/idpasslite.dir/ \
            --directory build/debug/lib/tests/CMakeFiles/idpasstests.dir/ \
            --directory build/debug/lib/src/CMakeFiles/idpasslite.dir/jni/ \
            --output-file build/cov.info
    lcov --extract build/cov.info "$project/lib/*" -o build/cov_filter1.info
    lcov --remove build/cov_filter1.info "*googletest*" -o build/cov_idpass.info
    echo
    echo "*******************************"
    echo "Generating code coverage report"
    echo "*******************************"
    rm -rf build/html/ build/html.tar.gzip
    genhtml build/cov_idpass.info -o build/html/
    tar zcvpf build/html.tar.gzip build/html

    # Commenting out these Cobertura coverage report
    # XML format
    # https://github.com/eriwen/lcov-to-cobertura-xml
    #
    #rm -rf build/test_results/demangle/
    #rm -rf build/test_results/nomangle/
    #mkdir -p build/test_results/demangle/
    #mkdir -p build/test_results/nomangle/
    #
    #python /home/circleci/project/scripts/lcov_cobertura.py \
    #    build/cov_idpass.info \
    #    --base-dir build/debug/lib/src/CMakeFiles/idpasslite.dir \
    #    --output build/test_results/demangle/results.xml \
    #    --demangle
    #
    #python3 /home/circleci/project/scripts/lcov_cobertura.py \
    #    build/cov_idpass.info \
    #    --base-dir build/debug/lib/src/CMakeFiles/idpasslite.dir \
    #    --output build/test_results/nomangle/results.xml
}

build_macos() {
    echo "*************************************"
    echo "Building macos libidpasslite.so ..."
    echo "*************************************"
    sleep 3
    mkdir -p build/macos && cd build/macos
    cmake -DCMAKE_BUILD_TYPE=Release -DTESTAPP=1 -DCMAKE_POSITION_INDEPENDENT_CODE=1 -DCMAKE_ANDROID_ARCH_ABI=macos -DEMBED_MODELS=1 ../..
    cmake --build .
    [ $? -ne 0 ] && return 1
    cd - >/dev/null

    echo "********************************"
    echo "Executing final test for release"
    echo "********************************"
    build/macos/lib/tests/idpasstests build/macos/lib/tests/data/
    if [ $? -ne 0 ];then
        return 1
    fi

    echo
    ls -lh build/macos/lib/src/libidpasslite.dylib
}

build_release() {
    echo "*************************************"
    echo "Building release libidpasslite.so ..."
    echo "*************************************"
    sleep 3
    #rm -rf build/release
    mkdir -p build/release && cd build/release
    cmake -DCMAKE_BUILD_TYPE=Release -DTESTAPP=1 -DCMAKE_POSITION_INDEPENDENT_CODE=1 -DEMBED_MODELS=1 ../..
    cmake --build .
    [ $? -ne 0 ] && return 1
    cd - >/dev/null

    echo "********************************"
    echo "Executing final test for release"
    echo "********************************"
    build/release/lib/tests/idpasstests build/release/lib/tests/data/
    if [ $? -ne 0 ];then
        return 1
    fi

    echo
    ls -lh build/release/lib/src/libidpasslite.so
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
        shift
        build_android $@
        ;;
        *)
        build_debug
        esac
    else
        ####################
        # get latest updates
        docker pull typelogic/circleci-android:latest

        docker run -it --user $(id -u):$(id -g) --rm \
            -v `pwd`:/home/circleci/project \
            -e API_LEVEL=23 \
            -w /home/circleci/project/ \
            typelogic/circleci-android:latest \
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
            #rm -rf $builddir
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
                -DWITH_JNI=1 \
                -DANDROID_CPP_FEATURES="rtti exceptions" ../..

            cmake --build .

            echo "***********************************"
            echo "--- Done building Android $abi ---"
            echo "***********************************"
            cd - >/dev/null
            sleep 3
        done
    else
        echo "*** Building selected Android architectures ***"
        sleep 3
        for abi in $@;do
            case "$abi" in
            x86|x86_64|armeabi-v7a|arm64-v8a)
            echo
            echo "*** Building Android architectures $abi ***"
            sleep 3
            local builddir=build/android.$abi
            #rm -rf $builddir
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
                -DWITH_JNI=1 \
                -DANDROID_CPP_FEATURES="rtti exceptions" ../..

            cmake --build .

            echo "***********************************"
            echo "--- Done building Android $abi ---"
            echo "***********************************"
            cd - >/dev/null
            ;;

            *)
            echo
            echo "Skipping unknown android arch $abi"
            echo
            esac
        done
    fi
}

########################
# main entrypoint here #
########################

if [ $# -eq 0 ];then
    build_inside_container
else
    case "$1" in 
    dependencies)
    build_dependencies $@
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

    macos)
    build_macos
    ;;

    *)
    echo
    echo "Unrecognized option"
    echo "Choose: desktop | debug | release | android [x86 | x86_64 | armeabi-v7a | arm64-v8a] | dependencies"
    ;;
    esac
fi


