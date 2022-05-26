### Step debug in VSCode IDE:

```
cd python-wrap
./code.sh
```

The below `.py` files are auto-generated from the [library's proto files](https://github.com/idpass/idpass-lite/tree/python-wrap/lib/src/proto):

- api_pb2.py
- idpasslite_pb2.py

via command `dependencies/build/desktop/bin/protoc --proto_path=lib/src/proto --python_out=myoutdir lib/src/proto/api.proto lib/src/proto/idpasslite.proto`.
It's recommended to use the library's provided `protoc` compiler to ensure compatibility. The `protoc` regeneration is only needed when the `*.proto` files changes. The `libidpasslite.so` library is the output of `./build.sh desktop`. 
