#!/bin/sh
#

export LD_LIBRARY_PATH=`pwd`/lib:$LD_LIBRARY_PATH
python3 main.py

ls -l qrcode.svg
