#!/bin/sh
#

API_LEVEL=23

iscontainer() {
    cat /proc/1/cgroup | grep -w docker > /dev/null
    return $?
}

build_libheaders() {
    if iscontainer; then
        scripts/build.libheaders.sh
    else
        # get latest updates
        #docker pull typelogic/android:latest

        p=/home/circleci/project
        docker run -it --user $(id -u):$(id -g) --rm \
            -v `pwd`:$p \
            -e API_LEVEL=$API_LEVEL \
            typelogic/android:latest \
            $p/scripts/build.libheaders.sh
    fi
}

build_apps_idpassapi() {
    if iscontainer; then
        scripts/build.apps.idpassapi.sh
    else
        # get latest updates
        #docker pull typelogic/android:latest

        p=/home/circleci/project
        docker run -it --user $(id -u):$(id -g) --rm \
            -v `pwd`:$p \
            -e API_LEVEL=$API_LEVEL \
            typelogic/android:latest \
            $p/scripts/build.apps.idpassapi.sh
    fi
}

case "$1" in 
libheaders)
build_libheaders
;;

all)
build_libheaders
build_apps_idpassapi
;;

*)
build_apps_idpassapi
;;
esac
