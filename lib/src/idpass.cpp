#include "dlibapi.h"
#include "sodium.h"
#include "proto/card_access/card_access.pb.h"
#include "qrcode.h"
#include "bin16.h"
#include "helper.h"
#include "dxtracker.h"

#include <jni.h>

#include <array>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iterator>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <list>

#ifdef ANDROID
#include <android/log.h>

#define LOGI(...) ((void)__android_log_print( \
    ANDROID_LOG_INFO, "idpass::idpass", __VA_ARGS__))
#else
#define LOGI(...)
#endif

#ifdef _WIN32
#define MODULE_API __declspec(dllexport)
#else
#define MODULE_API
#endif

#ifdef _IDPASS_JNI_
extern JNINativeMethod IDPASS_JNI[];
extern int IDPASS_JNI_TLEN;
#endif

// Visual Studio Settings
// [Debug]
// preprocessor=_IDPASS_JNI_;DLIB_JPEG_SUPPORT;SODIUM_STATIC;SODIUM_EXPORT=;_CRT_SECURE_NO_WARNINGS;
// include_directories=c:/idpass_deps/debug/include;C:/idpass_deps/debug/include/dlib/external/libjpeg;C:/Program Files/Java/jdk1.8.0_231/include/win32;C:/Program Files/Java/jdk1.8.0_231/include 
// runtime_library=/MTd
// linker_directories=c:/idpass_deps/debug/lib
// linker_input=libprotobufd.lib;libsodium.lib;dlib19.19.99_debug_64bit_msvc1925.lib;dlibmodels.lib 
//
// [Release]
// preprocessor=_IDPASS_JNI_;DLIB_JPEG_SUPPORT;SODIUM_STATIC;SODIUM_EXPORT=;_CRT_SECURE_NO_WARNINGS
// include_directories=c:/idpass_deps/release/include;c:/idpass_deps/release/include/dlib/external/libjpeg;C:/Program Files/Java/jdk1.8.0_231/include/win32;C:/Program Files/Java/jdk1.8.0_231/include
// runtime_library=/MT
// linker_directories=c:/idpass_deps/release/lib
// linker_input=libprotobuf.lib;libsodium.lib;dlib19.19.99_release_64bit_msvc1925.lib;dlibmodels.lib

//========================================
// `strings libidpass.so | grep DXTRACKER`
// tells the commit hash that built
// this library
char dxtracker[] = DXTRACKER;

//===============================================
// The JNI_OnLoad allows for a well-organized and
// flexible mechanism to map native methods in Java
// to a C method table. The only minimum requirements
// are:
//     - Java native method name and signature must
//       match as in the C method table row
// 
//     - Pass the full package class name into the
//       map_JNI function below.
// 
// The JNI_OnLoad is called only once during
// System.loadLibrary().
jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    static bool runonce = false;
    if (runonce) {
        return JNI_VERSION_1_6;
    }
    runonce = true;

    JNIEnv* env;

    if (vm->GetEnv(
        reinterpret_cast<void**>(&env), 
        JNI_VERSION_1_6
    ) != JNI_OK) {
        return JNI_ERR;
    }
    
    // Create re-usable local function for mapping JNIs to method tables
    auto map_JNI = [&env](const char* cls, JNINativeMethod* table, int n) {
        jint ret = 1;
        jclass clazz = env->FindClass(cls);
        if (clazz) {
            ret = env->RegisterNatives(clazz, table, n);
            env->DeleteLocalRef(clazz);
        }
        if (ret != 0) {
            throw "add_JNI failed";
        }
    };

    // Map org.idpass.IDPass Java native methods to C method table
    // More than one JNI can be mapped
    try {
#ifdef _IDPASS_JNI_
        map_JNI("org/idpass/IDPass", &IDPASS_JNI[0], IDPASS_JNI_TLEN);
#endif
    } catch (...) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}

// Library instance context using vector m to auto-manage memory 
struct Context 
{
    std::mutex ctxMutex;
    std::vector<std::vector<unsigned char>> m;

    std::array<unsigned char, crypto_aead_chacha20poly1305_IETF_KEYBYTES> encryptionKey; // 32
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> signatureKey; // 64
    std::list<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>> verificationKeys; // 32n

    float facediff_half;
    float facediff_full;
    bool fdimension; // 128/4 if true else 64/2
    int qrcode_ecc;

    unsigned char* NewByteArray(int n) 
    {
        m.emplace_back(n);
        return m.back().data();
    }

    void ReleaseByteArray(unsigned char* addr)
    {
        std::vector<std::vector<unsigned char>>::iterator mit;
        for (mit = m.begin(); mit != m.end();) {
            if (mit->data() == addr) {
                mit = m.erase(mit);
                return;
            } else {
                mit++;
            }
        }
    }
};

namespace M
{
    std::mutex mtx;
    std::vector<Context*> context;

    Context* newContext()
    {
        std::lock_guard<std::mutex> guard(mtx);
        Context* c = new Context;
        context.push_back(c);
        return c;
    }
};

#ifdef __cplusplus
extern "C" {
#endif


//=============    
// Description:
// card_encryption_key : used to encrypt the card data
// card_signature_key  : used to sign the IDPassCard in the SignedIDPassCard object
// verification_keys   : list of trusted signerPublicKey
MODULE_API void* idpass_api_init(unsigned char* card_encryption_key,
                                 int card_encryption_key_len,
                                 unsigned char* card_signature_key,
                                 int card_signature_key_len,
                                 unsigned char* verification_keys,
                                 int verification_keys_len)
{
    Context* context = M::newContext();

    if (!card_encryption_key || !card_signature_key || !verification_keys
        || card_encryption_key_len != crypto_aead_chacha20poly1305_IETF_KEYBYTES
        || card_signature_key_len  != crypto_sign_SECRETKEYBYTES
        || verification_keys_len < crypto_sign_PUBLICKEYBYTES 
        || verification_keys_len % crypto_sign_PUBLICKEYBYTES != 0
    ) {
        LOGI("invalid keys");
        return nullptr;
    }

    if (sodium_init() < 0) {
        LOGI("sodium_init failed");
        return nullptr;
    }

    std::memcpy(
        context->encryptionKey.data(),
        card_encryption_key,
        crypto_aead_chacha20poly1305_IETF_KEYBYTES); // 32

    std::memcpy( 
        context->signatureKey.data(),
        card_signature_key,
        crypto_sign_SECRETKEYBYTES); // 64

    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> public_key; // 32
    int nkeys = verification_keys_len / crypto_sign_PUBLICKEYBYTES;
    for (int i = 0; i < nkeys; i++) {
        std::copy(
            verification_keys + i * crypto_sign_PUBLICKEYBYTES,
            verification_keys + i * crypto_sign_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES,
            std::begin(public_key));
        context->verificationKeys.push_back(public_key);
    }

    context->facediff_half = 0.42; 
    context->facediff_full = 0.60;
    context->fdimension = false; // defaults to 64/2
    context->qrcode_ecc = ECC_MEDIUM;

    return static_cast<void*>(context);
}

MODULE_API
void idpass_api_freemem(void* self, unsigned char* buf)
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);

    context->ReleaseByteArray(buf);
}

/***********
Description:
Returns the encrypted protobuf ecard, ie
an encrypted SignedIDPassCard. 

Format is: nonce header + encrypted bytes*/
MODULE_API unsigned char*
idpass_api_create_card_with_face(void* self,
                                 int* outlen,
                                 const char* surname,
                                 const char* given_name,
                                 const char* date_of_birth,
                                 const char* place_of_birth,
                                 const char* extras,
                                 char* photo,
                                 int photo_len,
                                 const char* pin)
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);
    *outlen = 0;

    unsigned char* eSignedIdpasscardbuf = nullptr;
#ifdef _FIXVALS_
    unsigned long int epochSeconds = 0;
#else
    unsigned long int epochSeconds = std::time(nullptr);
#endif

    float faceArray[128];
    int year, month, day;
    // 1970/12/25
    sscanf(date_of_birth, "%d %*c %d %*c %d", &year, &month, &day); 

    if (dlib_api::computeface128d(photo, photo_len, faceArray) != 1) {
        LOGI("idpass_api_create_card_with_face: fail");
        return nullptr;
    }

    idpass::Date dob;
    dob.set_year(year);
    dob.set_month(month);
    dob.set_day(day);

    idpass::CardAccess access;
    access.set_pin(pin);

    if (context->fdimension) {
        // full
        unsigned char fdim_full[128 * 4];
        bin16::f4_to_f4b(faceArray, 128, fdim_full);
        access.set_face(fdim_full, sizeof fdim_full);
    } else {
        // half
        unsigned char fdim_half[64 * 2];
        bin16::f4_to_f2b(faceArray, 64, fdim_half);
        // helper_hexdump(faceArrayBuf, 64*2, "faceArrayBuf");
        access.set_face(fdim_half, sizeof fdim_half);
    }

    idpass::CardDetails details;
    details.set_surname(surname);
    details.set_givenname(given_name);
    details.set_placeofbirth(place_of_birth);
    details.set_createdat(epochSeconds);
    details.mutable_dateofbirth()->CopyFrom(dob);

    std::string kvlist = extras;
    auto x = helper::parseToMap(kvlist);

    for (auto& q : x) {
        idpass::Pair* pp = details.add_extra();
        pp->set_key(q.first);
        pp->set_value(q.second);
    }

#ifdef _FIXVALS_
    unsigned char ed25519_pk[] = {
        0x8b, 0xf0, 0x65, 0xb1, 0x06, 0x11, 0x5f, 0x13, 
        0x95, 0x6e, 0xbf, 0xf2, 0x9b, 0x8c, 0xdc, 0x33, 
        0xff, 0xc3, 0x63, 0x99, 0x12, 0x2b, 0x06, 0x4d, 
        0x49, 0x3d, 0xe1, 0x9d, 0xa3, 0x1f, 0xca, 0x9a};

    unsigned char ed25519_skpk[] = {
        0x6f, 0x5c, 0x86, 0x15, 0x21, 0x4d, 0x20, 0xa9, // <-- sk
        0x3f, 0xab, 0x64, 0xf7, 0x05, 0xee, 0x07, 0xda, 
        0x9d, 0x13, 0x56, 0x28, 0x7d, 0xe2, 0x31, 0xfe, 
        0x25, 0xe2, 0xef, 0x02, 0xc8, 0xea, 0x0c, 0x1a,
        0x8b, 0xf0, 0x65, 0xb1, 0x06, 0x11, 0x5f, 0x13, // <-- pk
        0x95, 0x6e, 0xbf, 0xf2, 0x9b, 0x8c, 0xdc, 0x33, 
        0xff, 0xc3, 0x63, 0x99, 0x12, 0x2b, 0x06, 0x4d, 
        0x49, 0x3d, 0xe1, 0x9d, 0xa3, 0x1f, 0xca, 0x9a};
#else
    // ed25519_skpk is a concat of the form: sk + pk
    unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES];   // 32
    unsigned char ed25519_skpk[crypto_sign_SECRETKEYBYTES]; // 64
    crypto_sign_keypair(ed25519_pk, ed25519_skpk);
#endif

    idpass::IDPassCard card;
    card.mutable_access()->CopyFrom(access);
    card.mutable_details()->CopyFrom(details);
    card.set_encryptionkey(ed25519_skpk, crypto_sign_SECRETKEYBYTES);

    int buf_len = card.ByteSizeLong();
    unsigned char* buf = new unsigned char[buf_len];

    if (!card.SerializeToArray(buf, buf_len)) {
        LOGI("serialize error1");
        delete[] buf;
        return nullptr;
    }

    unsigned char* signature = new unsigned char[crypto_sign_BYTES];
    unsigned long long signature_len;

    // sign the idpass::IDPassCard object with sig_skpk
    if (crypto_sign_detached(
            signature, 
            &signature_len, 
            buf, 
            buf_len, 
            context->signatureKey.data()) 
    != 0) {
        LOGI("crypto_sign error");
        delete[] buf;
        return nullptr;
    }

    delete[] buf; 

    idpass::SignedIDPassCard signedCard;
    signedCard.mutable_card()->CopyFrom(card);
    signedCard.set_signature(signature, signature_len);

    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_ed25519_sk_to_pk(public_key, context->signatureKey.data());

    signedCard.set_signerpublickey(public_key, crypto_sign_PUBLICKEYBYTES);

    delete[] signature;

    buf_len = signedCard.ByteSizeLong();
    buf = new unsigned char[buf_len];

    if (!signedCard.SerializeToArray(buf, buf_len)) {
        LOGI("serialize error2");
        delete[] buf;
        return nullptr;
    }

#ifdef _FIXVALS_
    unsigned char nonce[] = {
        0xd9, 0xc3, 0xf0, 0x16, 0x81, 0xf5, 0x77, 0x9f, 
        0x96, 0xc6, 0x42, 0x00};
#else
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES]; // 12
    randombytes_buf(nonce, sizeof nonce);
#endif

    int lenn = buf_len + crypto_aead_chacha20poly1305_IETF_ABYTES;
    eSignedIdpasscardbuf = new unsigned char[lenn];
    unsigned long long ciphertext_len = 0;

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            eSignedIdpasscardbuf,
            &ciphertext_len,
            buf,
            buf_len,
            NULL,
            0,
            NULL,
            nonce,
            context->encryptionKey.data())
    != 0) {
        LOGI("ietf_encrypt failed");
        delete[] buf;
        delete[] eSignedIdpasscardbuf;
        return nullptr;
    }

    delete[] buf;
    const int nonce_plus_eSignedIdpasscardbuf_len = sizeof nonce + ciphertext_len;
    unsigned char* nonce_plus_eSignedIdpasscardbuf
        //= context->NewByteArray(sizeof nonce + ciphertext_len);
        = new unsigned char[nonce_plus_eSignedIdpasscardbuf_len];

    std::memcpy(
        nonce_plus_eSignedIdpasscardbuf, 
        nonce, 
        sizeof nonce);

    std::memcpy(
        nonce_plus_eSignedIdpasscardbuf + sizeof nonce,
        eSignedIdpasscardbuf,
        ciphertext_len);

    delete[] eSignedIdpasscardbuf;

    // HERE ....
    buf_len = details.ByteSizeLong();
    buf = new unsigned char[buf_len];

    if (!details.SerializeToArray(buf, buf_len)) {
        LOGI("serialize error1");
        delete[] buf;
        delete[] nonce_plus_eSignedIdpasscardbuf;
        return nullptr;
    }

    signature = new unsigned char[crypto_sign_BYTES];

    // sign the idpass::IDPassCard object with sig_skpk
    if (crypto_sign_detached(
            signature, 
            &signature_len, 
            buf, 
            buf_len, 
            context->signatureKey.data()) 
    != 0) {
        LOGI("crypto_sign error");
        delete[] buf;
        delete[] nonce_plus_eSignedIdpasscardbuf;
        delete[] signature;
        return nullptr;
    }

    idpass::PublicSignedIDPassCard publicSignedCard;
    publicSignedCard.mutable_details()->CopyFrom(details);
    publicSignedCard.set_signature(signature, signature_len);
    publicSignedCard.set_signerpublickey(public_key, crypto_sign_PUBLICKEYBYTES);

    delete[] signature;
    delete[] buf;

    idpass::IDPassCards idpassCards;
    idpassCards.mutable_publiccard()->CopyFrom(publicSignedCard);
    idpassCards.set_encryptedcard(nonce_plus_eSignedIdpasscardbuf, nonce_plus_eSignedIdpasscardbuf_len);

    delete[] nonce_plus_eSignedIdpasscardbuf;

    buf_len = idpassCards.ByteSizeLong();
    buf = context->NewByteArray(buf_len);

    if (!idpassCards.SerializeToArray(buf, buf_len)) {
        LOGI("serialize error9");
        context->ReleaseByteArray(buf);
        return nullptr;
    }

    *outlen = buf_len;
    return buf;
}

// Returns CardDetails object if face matches
MODULE_API unsigned char*
idpass_api_verify_card_with_face(void* self,
                                 int* outlen,
                                 unsigned char* encrypted_card,
                                 int encrypted_card_len,
                                 char* photo,
                                 int photo_len)
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);
    *outlen = 0;

    idpass::SignedIDPassCard signedCard;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->encryptionKey.data(),
                             context->signatureKey.data(),
                             context->verificationKeys,
                             signedCard)) {
        return nullptr;
    }

    idpass::CardAccess access = signedCard.card().access();
    double face_diff = helper::computeFaceDiff(photo, photo_len, access.face());
    double threshold = access.face().length() == 128 * 4 ? context->facediff_full :
                                                       context->facediff_half;
    if (face_diff <= threshold) {
        idpass::CardDetails details = signedCard.card().details();
        int n = details.ByteSizeLong();
        unsigned char* buf = context->NewByteArray(n);

        if (details.SerializeToArray(buf, n)) {
            *outlen = n;
            return buf;
        }
    }

    return nullptr;
}

// returns CardDetails object if pin matches
MODULE_API unsigned char*
idpass_api_verify_card_with_pin(void* self,
                                int* outlen,
                                unsigned char* encrypted_card,
                                int encrypted_card_len,
                                const char* pin)
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);
    *outlen = 0;

    idpass::SignedIDPassCard signedCard;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->encryptionKey.data(),
                             context->signatureKey.data(),
                             context->verificationKeys,
                             signedCard)) {
        return nullptr;
    }

    idpass::CardAccess access = signedCard.card().access();

    if (access.pin().compare(pin) == 0) {
        idpass::CardDetails details = signedCard.card().details();
        int n = details.ByteSizeLong();
        unsigned char* buf = context->NewByteArray(n);

        if (details.SerializeToArray(buf, n)) {
            *outlen = n;
            return buf;
        }
    }

    LOGI("idpass_api_verify_card_with_pin: fail");
    return nullptr;
}

/*
Description:
This function encrypts the plaintext denoted by 'data' using the
key inside 'encrypted_card'.
The return value is the nonce header + ciphertext.*/
MODULE_API unsigned char*
idpass_api_encrypt_with_card(void* self,
                             int* outlen,
                             unsigned char* encrypted_card,
                             int encrypted_card_len,
                             unsigned char* data,
                             int data_len)
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);
    *outlen = 0;

    unsigned char* ciphertext = nullptr;
    unsigned long long ciphertext_len = 0;

    idpass::SignedIDPassCard signedCard;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->encryptionKey.data(),
                             context->signatureKey.data(),
                             context->verificationKeys,
                             signedCard)) {
        return nullptr;
    }

    // convert ed25519 to curve25519 and use curve25519 for encryption
    const unsigned char* ed25519_skpk
        = (const unsigned char*)signedCard.card().encryptionkey().c_str();

    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];

    std::memcpy(
        ed25519_pk,
        ed25519_skpk + crypto_sign_ed25519_PUBLICKEYBYTES,
        crypto_sign_ed25519_PUBLICKEYBYTES);

    unsigned char x25519_pk[crypto_scalarmult_curve25519_BYTES]; // 32
    unsigned char x25519_sk[crypto_scalarmult_curve25519_BYTES]; // 32

    crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk);
    crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_skpk);

    ///////////////////////////////////////////////////////////////////////////
    ciphertext_len = crypto_box_MACBYTES + data_len; // 16+
    ciphertext = new unsigned char[ciphertext_len];

#ifdef _FIXVALS_
    unsigned char nonce[] = {
        0xf4, 0x29, 0x35, 0xfd, 0xd3, 0xdf, 0xab, 0xb0,
        0xc1, 0x8d, 0x28, 0xf9, 0x33, 0xef, 0xbc, 0x8c,
        0x20, 0xbd, 0x88, 0xf2, 0xd7, 0xb8, 0xa3, 0xef};
#else
    unsigned char nonce[crypto_box_NONCEBYTES]; // 24
    randombytes_buf(nonce, sizeof nonce);
#endif

    // Encrypt with our sk with an authentication tag of our pk
    if (crypto_box_easy(
            ciphertext, 
            data, 
            data_len, 
            nonce, 
            x25519_pk, 
            x25519_sk)
    != 0) {
        LOGI("crypto_box_easy: error");
        delete[] ciphertext;
        return nullptr;
    }
    ///////////////////////////////////////////////////////////////////////////

    unsigned char* nonce_plus_ciphertext
        = context->NewByteArray(sizeof nonce + ciphertext_len);

    std::memcpy(
        nonce_plus_ciphertext, 
        nonce, 
        sizeof nonce);

    std::memcpy(
        nonce_plus_ciphertext + sizeof nonce, 
        ciphertext, 
        ciphertext_len);

    delete[] ciphertext;

    *outlen = ciphertext_len + sizeof nonce;

    return nonce_plus_ciphertext;
}

MODULE_API unsigned char*
idpass_api_sign_with_card(void* self,
                          int* outlen,
                          unsigned char* encrypted_card,
                          int encrypted_card_len,
                          unsigned char* data,
                          int data_len)
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);
    *outlen = 0;

    unsigned char* signature = nullptr;

    idpass::SignedIDPassCard signedCard;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->encryptionKey.data(),
                             context->signatureKey.data(),
                             context->verificationKeys,
                             signedCard)) {
        return nullptr;
    }

    signature = context->NewByteArray(crypto_sign_BYTES);
    unsigned long long smlen;

    // use ed25519 to sign
    if (crypto_sign_detached(
            signature,
            &smlen,
            data,
            data_len,
            (const unsigned char*)signedCard.card().encryptionkey().c_str())
    != 0) {
        LOGI("crypto_sign: error");
        context->ReleaseByteArray(signature);
        return nullptr;
    }

    *outlen = smlen;
    return signature;
}

// Returns the QR Code encoding in bits with square dimension len
MODULE_API unsigned char* idpass_api_qrpixel(void* self,
                                             const unsigned char* data,
                                             int data_len,
                                             int* qrsize)
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);
    int buf_len = 0;

    unsigned char* buf = qrcode_getpixel(
        data, data_len, qrsize, &buf_len, context->qrcode_ecc);

    if (buf == nullptr) {
        LOGI("idpass_api_qrpixel: error");
        return nullptr;
    }

    // re-allocate & copy into our manage area
    unsigned char* pixel = context->NewByteArray(buf_len);
    std::memcpy(pixel, buf, buf_len);
    delete[] buf;

    return pixel;
}

//=================================================
// This is a generalized get/set API. The supported
// commands are:
//     - Set new float value to fdiff
//     - Get the current float value fdiff  used
//       in Dlib face recognition
//     - Get the current face dimension mode 
//       either it uses the full 128 floats with
//       4 bytes per float or the 64 floats with
//       2 bytes per float
//     - Change fdimension mode 
//     - Change QR Code ECC level
// 
// The first byte is the command, and the rest of
// the bytes are I/O to read input and write 
// output for this initial commands.
MODULE_API
void* idpass_api_ioctl(void* self,
                       int* outlen,
                       unsigned char* iobuf,
                       int iobuf_len)

{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);

    if (!iobuf || iobuf_len <= 0) {
        return nullptr;
    }

    if (outlen) {
        *outlen = 0;
    }
    
    unsigned char cmd = iobuf[0];
    switch (cmd) 
    {
        case 0x00: { // set new facediff value
            float facediff;
            bin16::f4b_to_f4(iobuf + 1, iobuf_len - 1, &facediff);
            if (context->fdimension) {
                context->facediff_full = facediff;
            } else {
                context->facediff_half = facediff;
            }
        } break;

        case 0x01: { // get current facediff value
            if (context->fdimension) {
                bin16::f4_to_f4b(&context->facediff_full, 1, iobuf + 1);
            } else {
                bin16::f4_to_f4b(&context->facediff_half, 1, iobuf + 1);
            }
        } break;

        case 0x02: { // set fdimension flag
            if (iobuf[1] == 0x00) {
                context->fdimension = false;
            } else if (iobuf[1] == 0x01) {
                context->fdimension = true;
            }
        } break;             

        case 0x03: { // get fdimension flag
            if (context->fdimension) {
                iobuf[1] = 0x01;
            } else {
                iobuf[1] = 0x00;
            }
        } break;             

        case 0x04: { // set QR Code ECC level
            switch (iobuf[1]) 
            {
            case 0x00: {
                context->qrcode_ecc = ECC_LOW;
            } break;     
            case 0x01: {
                context->qrcode_ecc = ECC_MEDIUM; // default
            } break;     
            case 0x02: {
                context->qrcode_ecc = ECC_QUARTILE;
            } break;     
            case 0x03: {
                context->qrcode_ecc = ECC_HIGH;
            } break;     
            }
        } break;
    }

    return nullptr;
}

MODULE_API int
idpass_api_face128d(void* self, char* photo, int photo_len, float* faceArray)
{
    Context* context = (Context*)self;
    // Dlib can handle multithreaded
    // std::lock_guard<std::mutex> guard(context->ctxMutex);
    return dlib_api::computeface128d(photo, photo_len, faceArray);
}

MODULE_API int idpass_api_face128dbuf(void* self,
                                      char* photo,
                                      int photo_len,
                                      unsigned char* buf)
{
    Context* context = (Context*)self;
    // Dlib can handle multithreaded
    // std::lock_guard<std::mutex> guard(context->ctxMutex);
    float f4[128];
    int face_count = dlib_api::computeface128d(photo, photo_len, f4);

    if (face_count == 1) {
        bin16::f4_to_f4b(f4, 128, buf);
    }

    return face_count;
}

MODULE_API int idpass_api_face64dbuf(void* self,
                                     char* photo,
                                     int photo_len,
                                     unsigned char* buf)
{
    Context* context = (Context*)self;
    // Dlib can handle multithreaded
    // std::lock_guard<std::mutex> guard(context->ctxMutex);
    float f4[128];
    int face_count = dlib_api::computeface128d(photo, photo_len, f4);

    if (face_count == 1) {
        bin16::f4_to_f2b(f4, 64, buf);
    }

    return face_count;
}

// Saves the QR Code encoding to a bitmap file
MODULE_API int idpass_api_saveToBitmap(void* self,
                                       unsigned char* data,
                                       int data_len,
                                       const char* bitmapfile)
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);

    return qrcode_saveToBitmap(data, data_len, bitmapfile);
}

MODULE_API
unsigned char* protobuf_test(void* self,
                             int* outlen,
                             const char* surname,
                             const char* given_name,
                             const char* date_of_birth,
                             const char* place_of_birth,
                             const char* extras)
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);

    unsigned long int epochSeconds = std::time(nullptr);
    idpass::CardDetails details;

    int year, month, day;
    sscanf(date_of_birth, "%d %*c %d %*c %d", &year, &month, &day); 

    details.set_surname(surname);
    details.set_givenname(given_name);
    details.set_placeofbirth(place_of_birth);
    details.set_createdat(epochSeconds);

    idpass::Date dob;

    dob.set_year(year);
    dob.set_month(month);
    dob.set_day(day);

    details.mutable_dateofbirth()->CopyFrom(dob);

    std::string kvlist = extras;

    auto x = helper::parseToMap(kvlist);

    for (auto& q : x) {
        idpass::Pair* pp = details.add_extra();
        pp->set_key(q.first);
        pp->set_value(q.second);
    }

    const int datalen = details.ByteSizeLong();
    unsigned char* data = context->NewByteArray(datalen);

    if (details.SerializeToArray(data, datalen)) {
        *outlen = datalen;
        return data;
    }

    return nullptr;
}

MODULE_API int idpass_api_addnum(int a, int b)
{
    return a + b;
}

#ifdef __cplusplus
}
#endif
