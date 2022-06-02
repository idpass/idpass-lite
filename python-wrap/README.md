### Test run in a backend deploy

All that is needed is inside the `python-wrap/` folder. So doing a `cp -a python-wrap/* /some/other/path/` followed by:

```
cd /home/other/path/
./run.sh
```

So, basically in `run.sh` we have:

```
test ID details -> main.py -> qrcode1.svg, qrcode2.svg
```

will generate an `qrcode1.svg` output file using a test identity detail in `ident1.json`, `ident2.json`


### Usage within another application

General description:

- Initialize `Reader` with a key set. Generated QR codes using the `demokeys.bin` key set shall be readable from the "Android Smartscanner mobile app".
- Given an identity details in `json` format, convert this `json` into it's corresponding protobuf message equivalent (Ident)
- Call `reader.create_card_with_face(identobj)` will return a `Card` object
- Calling `card.asQRCodeSVG()` will return a QR code representation of the card.
- Open this QR code SVG format from a browser, and scan it using the "ID PASS Smartscanner Android mobile app" 

```
keySet = KEYSET_fromFile("demokeys.bin")    # Load matching keyset 
reader = IDPassLite.Reader(keySet)          # create reader object associated with a key set
ident = getIdentFromJson("ident1.json")     # create ident object from an identity json
card  = reader.create_card_with_face(ident) # generate card from an ident object
svg = card.asQRCodeSVG()                    # generate SVG QR code from a card
open("qrcode.svg","w").write(svg)           # write SVG file to disc
```

### Step debug in VSCode IDE:

To develop further the python wrapping API using VSCode IDE:

```
cd python-wrap
./code.sh
```

Nothing to be done here, but just to explain some overiew where some files are coming from. The below `.py` files are auto-generated from the [library's proto files](https://github.com/idpass/idpass-lite/tree/python-wrap/lib/src/proto):

- api_pb2.py
- idpasslite_pb2.py

via command `dependencies/build/desktop/bin/protoc --proto_path=lib/src/proto --python_out=myoutdir lib/src/proto/api.proto lib/src/proto/idpasslite.proto`.
It's recommended to use the library's provided `protoc` compiler to ensure compatibility. The `protoc` regeneration is only needed when the `*.proto` files changes. The `libidpasslite.so` library is the output of `./build.sh desktop`. 

The `demokeys.bin` is a demo set of keys for inter-operable testing across apps. 

The `IDPassNative.py` loads `idpasslite.so` library. The library's methods defined in [idpass.h](https://github.com/idpass/idpass-lite/blob/python-wrap/lib/src/idpass.h) are mapped in `IDPassNative.py`. 

# Items TODO

- qrcode.cpp is not multithreaded when generating SVG
