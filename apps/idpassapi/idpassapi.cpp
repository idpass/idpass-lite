#include "dxtracker.h"
#include "dlibapi.h"
#include "helper.h"
#include "protogen/card_access.pb.h"
#include "sodium.h"
#include "bin16.h"

#include <array>
#include <ctime>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "qrcode.h"

#ifndef _WIN32
#ifdef __ANDROID__
#include <android/log.h>

#define LOGI(...)               \
    ((void)__android_log_print( \
        ANDROID_LOG_INFO, "dxlog::", __VA_ARGS__))
#else
#define LOGI(...)
#endif
#else
#define LOGI(...)
#endif

#ifdef _WIN32
#define MODULE_API __declspec(dllexport)
#else
#define MODULE_API
#endif

//char dxtracker[] = DXTRACKER;

struct Context {
    std::mutex ctxMutex;
    std::vector<std::vector<unsigned char>> m;

    std::array<unsigned char, crypto_aead_chacha20poly1305_IETF_KEYBYTES>
        encryptionKey; // 32
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> signatureKey; // 64
    std::vector<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>> // 32n
        verificationKeys;

    unsigned char* ByteArray(int n) {
        m.emplace_back(n);
        return m.back().data();
    }

    void eraseByteArray(unsigned char* addr) {
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

namespace M {
    std::mutex mtx;
    std::vector<Context*> context;

    Context* newContext() {
        std::lock_guard<std::mutex> guard(mtx);
        Context* c = new Context;
        context.push_back(c);
        return c;
    }
};

#ifdef __cplusplus
extern "C" {
#endif

/*
Description:
card_encryption_key : used to encrypt the card data
card_signature_key  : used to sign the IDPassCard in the SignedIDPassCard object
verification_keys   : list of trusted signerPublicKey
count               : of signerPublickKey */
MODULE_API void* idpass_api_init(unsigned char* card_encryption_key,
                                 unsigned char* card_signature_key,
                                 unsigned char* verification_keys,
                                 int count)
{
    Context* context = M::newContext();

    if (!card_encryption_key || !card_signature_key || !verification_keys) {
        LOGI("null keys");
        return nullptr;
    }

    if (sodium_init() < 0) {
        LOGI("sodium_init failed");
        return nullptr;
    }

    std::memcpy(context->encryptionKey.data(),
                card_encryption_key,
                crypto_aead_chacha20poly1305_IETF_KEYBYTES);

    std::memcpy(
        context->signatureKey.data(), card_signature_key, 
        crypto_sign_SECRETKEYBYTES);

    if (count > 0 && verification_keys) {
        context->verificationKeys.resize(count);
        std::memcpy(context->verificationKeys.data(),
                    verification_keys,
                    crypto_sign_PUBLICKEYBYTES * count);
    }

    return static_cast<void*>(context);
}

// Idpass__CardDetails*
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
                             signedCard)) {
        return nullptr;
    }

    idpass::CardAccess access = signedCard.card().access();
    double face_diff = helper::computeFaceDiff(photo, photo_len, access.face()); 

#ifndef FACE_DIFF
    double fdiff = 0.6;
#else
    double fdiff = FACE_DIFF; // 0.42
#endif

    if (face_diff <= fdiff) {
        idpass::CardDetails details = signedCard.card().details();
        int n = details.ByteSizeLong();
        unsigned char* buf = context->ByteArray(n); 

        if (details.SerializeToArray(buf, n)) {
            *outlen = n;
            return buf;
        }
    }

    return nullptr;
}

// Idpass__CardDetails*
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
                             signedCard)) {
        return nullptr;
    }

    idpass::CardAccess access = signedCard.card().access();

    if (access.pin().compare(pin) == 0) {
        idpass::CardDetails details = signedCard.card().details();
        int n = details.ByteSizeLong();
        unsigned char* buf = context->ByteArray(n);  

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
key denoted by 'encrypted_card'.
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
                             signedCard)) {
        return nullptr;
    }

    // convert ed25519 to curve25519 and use curve25519 to encrypt
    const unsigned char* ed25519_skpk
        = (const unsigned char*)signedCard.card().encryptionkey().c_str();

    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];

    std::memcpy(ed25519_pk,
                ed25519_skpk + crypto_sign_ed25519_PUBLICKEYBYTES,
                crypto_sign_ed25519_PUBLICKEYBYTES);

    unsigned char x25519_pk[crypto_scalarmult_curve25519_BYTES]; // 32
    unsigned char x25519_sk[crypto_scalarmult_curve25519_BYTES]; // 32

    int sodium_retval = crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk);
    crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_skpk);

    ///////////////////////////////////////////////////////////////////////////
    ciphertext_len = crypto_box_MACBYTES + data_len; // 16+
    ciphertext = new unsigned char[ciphertext_len];

    unsigned char nonce[crypto_box_NONCEBYTES]; // 24
    randombytes_buf(nonce, sizeof nonce);

    // Encrypt with our sk with an authentication tag of our pk
    if (crypto_box_easy(ciphertext, data, data_len, nonce, x25519_pk, x25519_sk)
        != 0) {
        LOGI("crypto_box_easy: error");
        delete[] ciphertext;
        return nullptr;
    }
    ///////////////////////////////////////////////////////////////////////////

    unsigned char* nonce_plus_ciphertext
        = context->ByteArray(sizeof nonce + ciphertext_len); 
    std::memcpy(nonce_plus_ciphertext, nonce, sizeof nonce);
    std::memcpy(
        nonce_plus_ciphertext + sizeof nonce, ciphertext, ciphertext_len);

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
                             signedCard)) {
        return nullptr;
    }

    signature
        = context->ByteArray(data_len + crypto_sign_BYTES); 
    unsigned long long smlen;

    // use ed25519 to sign
    if (crypto_sign(
            signature,
            &smlen,
            data,
            data_len,
            (const unsigned char*)signedCard.card().encryptionkey().c_str())
        != 0) {
        LOGI("crypto_sign: error");
        //delete[] signature;
        context->eraseByteArray(signature);
        return nullptr;
    }

    *outlen = smlen;

    return signature;
}

MODULE_API 
unsigned char* protobuf_test(void* self,
                             int* outlen,
                             const char* surname,
                             const char* given_name,
                             const char* date_of_birth,
                             const char* place_of_birth,
                             const char* extras
                             )
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);

    unsigned long int epochSeconds = 9;
    idpass::CardDetails details; 

    int year = 1970, month = 1, day = 1;

    sscanf(
        date_of_birth, "%d %*c %d %*c %d", &year, &month, &day); // 2020/12/25

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
    unsigned char* data = context->ByteArray(datalen); 

    if (details.SerializeToArray(data, datalen)) {
        *outlen = datalen;
        return data;
    }

    return nullptr;
}

/*
 Description:
 Returns the encrypted protobuf mesage of the card, ie
 an IDPassCard encrypted. Format is: nonce header + encrypted stuff */

// we need to encrypt SignedIDPassCard and not IDPassCard
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
#ifdef _FIXVALS
    unsigned long int epochSeconds = 0;
#else
    unsigned long int epochSeconds = std::time(nullptr);
#endif

    float faceArray[128];
    int year = 1970, month = 1, day = 1;

    sscanf(
        date_of_birth, "%d %*c %d %*c %d", &year, &month, &day); // 2020/12/25

    if (dlib_api::computeface128d(photo, photo_len, faceArray) != 1) {
        LOGI("idpass_api_create_card_with_face: fail");
        return nullptr;
    }

    idpass::Date dob; 

    dob.set_year(year);
    dob.set_month(month);
    dob.set_day(day);

    idpass::CardAccess access; 

#ifndef FACE_DIFF
    // full
    unsigned char faceArrayBuf_full[128 * 4];
    bin16::f4_to_f4b(faceArray, 128, faceArrayBuf_full);
    access.set_face(faceArrayBuf_full, sizeof faceArrayBuf_full);
#else
    // half 
    unsigned char faceArrayBuf[64 * 2];
    bin16::f4_to_f2b(faceArray, 64, faceArrayBuf); 
    //helper_hexdump(faceArrayBuf, 64*2, "faceArrayBuf");
    access.set_face(faceArrayBuf, sizeof faceArrayBuf);
#endif

    access.set_pin(pin);

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

    // ed25519_skpk is a concat of the form: sk + pk
    unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES]; // 32
    unsigned char ed25519_skpk[crypto_sign_SECRETKEYBYTES]; // 64
    int iret;
#ifdef _FIXVALS
    unsigned char fix_pk[] = {
        0x8b, 0xf0, 0x65, 0xb1, 0x06, 0x11, 0x5f, 0x13, 
        0x95, 0x6e, 0xbf, 0xf2, 0x9b, 0x8c, 0xdc, 0x33, 
        0xff, 0xc3, 0x63, 0x99, 0x12, 0x2b, 0x06, 0x4d, 
        0x49, 0x3d, 0xe1, 0x9d, 0xa3, 0x1f, 0xca, 0x9a};

    unsigned char fix_skpk[] = {
        0x6f, 0x5c, 0x86, 0x15, 0x21, 0x4d, 0x20, 0xa9, // <-- sk
        0x3f, 0xab, 0x64, 0xf7, 0x05, 0xee, 0x07, 0xda, 
        0x9d, 0x13, 0x56, 0x28, 0x7d, 0xe2, 0x31, 0xfe, 
        0x25, 0xe2, 0xef, 0x02, 0xc8, 0xea, 0x0c, 0x1a, 
        0x8b, 0xf0, 0x65, 0xb1, 0x06, 0x11, 0x5f, 0x13, // <-- pk
        0x95, 0x6e, 0xbf, 0xf2, 0x9b, 0x8c, 0xdc, 0x33, 
        0xff, 0xc3, 0x63, 0x99, 0x12, 0x2b, 0x06, 0x4d, 
        0x49, 0x3d, 0xe1, 0x9d, 0xa3, 0x1f, 0xca, 0x9a};

    std::memcpy(ed25519_pk, fix_pk, sizeof fix_pk); 
    std::memcpy(ed25519_skpk, fix_skpk, sizeof fix_skpk);
#else
    iret = crypto_sign_keypair(ed25519_pk, ed25519_skpk);
#endif


    idpass::IDPassCard card;
    card.mutable_access()->CopyFrom(access);
    card.mutable_details()->CopyFrom(details);
    card.set_encryptionkey(ed25519_skpk, crypto_sign_SECRETKEYBYTES);

    const int datalen = card.ByteSizeLong();
    unsigned char* data = new unsigned char[datalen];

    if (!card.SerializeToArray(data, datalen)) {
        LOGI("serialize error1");
        delete[] data;
        return nullptr;
    }

    unsigned char* sm = new unsigned char[datalen + crypto_sign_BYTES];
    unsigned long long smlen;

    int ret = crypto_sign(sm, &smlen, data, datalen, context->signatureKey.data());
    delete[] data;

    idpass::SignedIDPassCard signedCard;
    signedCard.mutable_card()->CopyFrom(card);
    signedCard.set_signature(sm, smlen);

    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_ed25519_sk_to_pk(public_key, context->signatureKey.data());

    signedCard.set_signerpublickey(public_key, crypto_sign_PUBLICKEYBYTES);

    delete[] sm;

    const int data2len = signedCard.ByteSizeLong();
    unsigned char* data2 = new unsigned char[data2len];

    if (!signedCard.SerializeToArray(data2, data2len)) {
        LOGI("serialize error2");
        delete[] data2;
        return nullptr;
    }

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];

#ifdef _FIXVALS
    unsigned char fix_nonce[] = {
        0xd9, 0xc3, 0xf0, 0x16, 0x81, 0xf5, 0x77, 0x9f, 
        0x96, 0xc6, 0x42, 0x00};
    std::memcpy(nonce, fix_nonce, sizeof fix_nonce);
#else
    randombytes_buf(nonce, sizeof nonce);
#endif

    int lenn = data2len + crypto_aead_chacha20poly1305_IETF_ABYTES;
    eSignedIdpasscardbuf = new unsigned char[lenn];
    unsigned long long ciphertext_len = 0;

    iret = crypto_aead_chacha20poly1305_ietf_encrypt(eSignedIdpasscardbuf,
                                                     &ciphertext_len,
                                                     data2,
                                                     data2len,
                                                     NULL,
                                                     0,
                                                     NULL,
                                                     nonce,
                                                     context->encryptionKey.data());

    unsigned char* nonce_plus_eSignedIdpasscardbuf = context->ByteArray(sizeof nonce + ciphertext_len);
    std::memcpy(nonce_plus_eSignedIdpasscardbuf, nonce, sizeof nonce);
    std::memcpy(nonce_plus_eSignedIdpasscardbuf + sizeof nonce,
                eSignedIdpasscardbuf,
                ciphertext_len);

    *outlen = sizeof nonce + ciphertext_len;

    delete[] data2;
    delete[] eSignedIdpasscardbuf;

    return nonce_plus_eSignedIdpasscardbuf;
}

MODULE_API int idpass_api_face128d(void* self,
                                   char* photo,
                                   int photo_len,
                                   float* faceArray)
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
    unsigned char* data, int data_len, const char* bitmapfile)
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);

    return qrcode_saveToBitmap(data, data_len, bitmapfile);
}

// Returns the QR Code encoding in bits with square dimension len
MODULE_API unsigned char* idpass_api_qrpixel(void* self,
    const unsigned char* data, int data_len, int* qrsize)
{
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);
    int buf_len = 0;
    unsigned char* buf = qrcode_getpixel(data, data_len, qrsize, &buf_len);

    if (buf == nullptr) {
        LOGI("idpass_api_qrpixel: error");
        return nullptr;
    }

    // re-allocate & copy into our manage area
    unsigned char* pixel = context->ByteArray(buf_len);
    std::memcpy(pixel, buf, buf_len); 
    delete[] buf;

    return pixel;
}

MODULE_API int idpass_api_addnum(int a, int b)
{
    return a + b;    
}
 
#ifdef __cplusplus
}
#endif
