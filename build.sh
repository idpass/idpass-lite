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
            -v `pwd`:$p \
            -e API_LEVEL=$API_LEVEL \
            newlogic42/circleci-android:latest \
            $p/scripts/build.dependencies.sh
    fi
}

build_lib_idpassapi() {
    if iscontainer; then
        scripts/build.lib.idpassapi.sh
    else
        # get latest updates
        #docker pull newlogic42/circleci-android:latest
        docker run -it --user $(id -u):$(id -g) --rm \
            -v `pwd`:$p \
            -e API_LEVEL=$API_LEVEL \
            newlogic42/circleci-android:latest \
            $p/scripts/build.lib.idpassapi.sh
    fi
}

case "$1" in 
dependencies)
build_dependencies
;;

all)
build_dependencies
build_lib_idpassapi
;;

*)
build_lib_idpassapi
;;
esac
