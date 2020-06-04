#!/bin/sh
#

rm -f org/idpass/api/IDPassAPI.class
rm -rf build/
mkdir -p build/
cd build
cmake ..
cmake --build .
cd ..

jars=$(find jars/ -type f | tr '\n' ':')

javac -cp $jars org/idpass/api/IDPassAPI.java

java \
    -Djava.library.path=build \
    -Djna.tmpdir=/tmp/ \
    -cp $jars org.idpass.api.IDPassAPI /tmp/qrcode.bmp /tmp/qrcode.dat

rm -f org/idpass/api/IDPassAPI.class
rm -rf build/
