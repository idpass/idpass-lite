### Test run in a backend deploy

All that is needed is inside the `python-wrap/` folder. So doing a `cp -a python-wrap/* /some/other/path/` followed by:

```
cd /home/other/path/
./run.sh
```

So, basically in `run.sh` we have:

```
test ID details -> main.py -> qrcode.svg
```

will generate an `qrcode.svg` output file using a test identity detail in `main.py`. 

### Step debug in VSCode IDE:

To develop further the python wrapping API using VSCode IDE:

```
cd python-wrap
./code.sh
```

The below `.py` files are auto-generated from the [library's proto files](https://github.com/idpass/idpass-lite/tree/python-wrap/lib/src/proto):

- api_pb2.py
- idpasslite_pb2.py

via command `dependencies/build/desktop/bin/protoc --proto_path=lib/src/proto --python_out=myoutdir lib/src/proto/api.proto lib/src/proto/idpasslite.proto`.
It's recommended to use the library's provided `protoc` compiler to ensure compatibility. The `protoc` regeneration is only needed when the `*.proto` files changes. The `libidpasslite.so` library is the output of `./build.sh desktop`. 

The `demokeys.bin` is a demo set of keys for inter-operable testing across apps. 

The `IDPassNative.py` loads `idpasslite.so` library. The library's methods defined in [idpass.h](https://github.com/idpass/idpass-lite/blob/python-wrap/lib/src/idpass.h) are mapped in `IDPassNative.py`. 


