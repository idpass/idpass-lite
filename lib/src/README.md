# Description

The two dat files inside the `models` folder are compiled to become a static library `libmodels.a`.
The `dlibapi.cpp` does an extern reference to the huge array inside `libmodels.a`. 

Implemented functions:
- `create_card_with_face`
- `verify_card_with_face`
- `verify_card_with_pin`
- `encrypt_with_card`
- `sign_with_card`

## Description

The **libidpassapi.so** core components:
- `protobuf` 
- `Dlib`
- `libsodium`
- QR code generator

