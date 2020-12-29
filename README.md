# ID PASS Lite

[![CircleCI](https://circleci.com/gh/idpass/idpass-lite.svg?style=svg&circle-token=937634c8f42536396097ea8c04097035b9c9a509)](https://circleci.com/gh/idpass/idpass-lite)

A library to create and issue biometrically-binding QR code identity cards.

![Alt text](idpasslite_qr.png?raw=true "api")

## Getting started

This library can be used in C and C++ projects. Download `libidpasslite.so` from the [Releases](https://github.com/idpass/idpass-lite/releases) page or [build it from source](https://github.com/idpass/idpass-lite/wiki/Building-from-source), then add it to the project that will use it.

Additional documentation on how to use this library can be found in the [wiki](https://github.com/idpass/idpass-lite/wiki).

Other languages are also supported through our wrapper packages:

- Java: [idpass-lite-java](https://github.com/idpass/idpass-lite-java)

## Usage

Add the library to the project's `CMakeLists.txt`:

```txt
TARGET_LINK_LIBRARIES(idpasslite)
```

Then include the library's header files into the project:

```cpp
#include "idpass.h"
#include "proto/api/api.pb.h"
#include "proto/idpasslite/idpasslite.pb.h"
```

The library needs to be initialized before it can be used. Add the following into the project code:

```cpp
void initialize_idpass()
{
    // Generate cryptographic keys
    unsigned char signaturekey[64];
    unsigned char encryptionkey[32];

    idpass_lite_generate_secret_signature_key(signaturekey, 64);
    idpass_lite_generate_encryption_key(encryptionkey, 32);

    // Create a keyset using the generated keys
    api::KeySet keyset;
    keyset.set_encryptionkey(encryptionkey, 32);
    keyset.set_signaturekey(signaturekey, 64);

    // Serialize the keyset into a byte array
    std::vector<unsigned char> keysetbuf(keyset.ByteSizeLong());
    keyset.SerializeToArray(keysetbuf.data(), keysetbuf.size());

    // Call the library's main initialization API
    void* context = idpass_lite_init(keysetbuf.data(), keysetbuf.size(), nullptr, 0);
}

int main() {
    initialize_idpass();
}
```

Now we can use the library in the project, for example in order to create an ID Pass Lite identity card for a new user:

```cpp
// Prepare protobuf object
api::Ident ident;

// Take a photo of the user
std::string filename = "userphoto.jpg";
std::ifstream photofile(filename, std::ios::binary);
std::vector<char> photo(std::istreambuf_iterator<char>{photofile}, {});

// Initialize protobuf object with the user's identity details
ident.set_surname("Doe");
ident.set_givenname("John");
ident.set_placeofbirth("Kibawe, Bukidnon");
ident.set_pin("12345");
ident.mutable_dateofbirth()->set_year(1978);
ident.mutable_dateofbirth()->set_month(12);
ident.mutable_dateofbirth()->set_day(17);
ident.set_photo(photo.data(), photo.size());

// Serialize protobuf object into a byte array
std::vector<unsigned char> identbuf(ident.ByteSizeLong());
ident.SerializeToArray(identbuf.data(), identbuf.size());

// Create an IDPASSLITE card for the user
int idcard_len;
unsigned char* idcard = idpass_lite_create_card_with_face(context,
    &idcard_len, identbuf.data(), identbuf.size());

// Save the IDASSLITE card as a QR code image
idpass_lite_saveToBitmap(context, idcard, idcard_len, "qrcode_id.bmp");
```

Please refer to the [API Reference](https://github.com/idpass/idpass-lite/wiki/API-Reference) for all the available methods provided by this library.

## Open source dependencies

- [libsodium](https://github.com/jedisct1/libsodium.git)
- [dlib](https://github.com/davisking/dlib.git)
- [protobuf](https://github.com/protocolbuffers/protobuf.git)
- [QRCode](https://github.com/ricmoo/QRCode)

## License

[Apache-2.0 License](LICENSE)
