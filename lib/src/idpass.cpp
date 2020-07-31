#include "idpass.h"
#include "Cert.h"
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
// `strings libidpasslite.so | grep DXTRACKER`
// tells the commit hash that built
// this library
char dxtracker[] = DXTRACKER;

std::mutex g_mutex;

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
        map_JNI("org/idpass/lite/IDPassReader", &IDPASS_JNI[0], IDPASS_JNI_TLEN);
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
    std::mutex mtx;
    std::vector<std::vector<unsigned char>> m;

    std::array<unsigned char, crypto_aead_chacha20poly1305_IETF_KEYBYTES> encryptionKey; // 32
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> signatureKey; // 64
    std::list<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>> verificationKeys; // 32n

    std::vector<Cert> root_certificates;     // 160n
    std::vector<Cert> intermed_certificates; // 128n
    //std::vector<Cert> certificates;

    float facediff_half;
    float facediff_full;
    bool fdimension; // 128/4 if true else 64/2
    int qrcode_ecc;

    unsigned char acl[1];

    unsigned char* NewByteArray(int n) 
    {
        std::lock_guard<std::mutex> guard(mtx);
        m.emplace_back(n);
        return m.back().data();
    }

    bool ReleaseByteArray(void* addr)
    {
        std::lock_guard<std::mutex> guard(mtx);
        std::vector<std::vector<unsigned char>>::iterator mit;
        for (mit = m.begin(); mit != m.end();) {
            if (mit->data() == addr) {
                mit = m.erase(mit);
                return true;
            } else {
                mit++;
            }
        }
        return false;
    }

    bool verify_chain(std::vector<Cert>& chain) 
    {
        auto in_root_certificates = [this](const Cert* c) {
            return std::find_if(
                root_certificates.begin(),
                root_certificates.end(),
                [&c](const Cert& m) -> bool {
                    return std::memcmp(m.pubkey, c->pubkey, 32) == 0;
                }) != root_certificates.end();
        };

        if (chain.size() == 0) {
            return false;
        }

        Cert* pCert = &chain.back();
        unsigned char* startkey = pCert->pubkey;

        while (pCert != nullptr) 
        {
            if (pCert->hasValidSignature()) {
                if (helper::isRevoked(REVOKED_KEYS, pCert->pubkey, 32)) {
                    return false;
                }
                if (!pCert->isRootCA()) {
                    pCert = pCert->getIssuer(chain, root_certificates);
                    if (pCert == nullptr
                        || std::memcmp(pCert->pubkey, startkey, 32) == 0) {
                        return false;
                    }

                    continue;

                } else {
                    return in_root_certificates(pCert);
                }
            } else {
                return false;
            }
        }

        return true;
    }

    Context()
    {
        //std::cout << " Context[" << this << "]" << std::flush << std::endl;    
    }

    ~Context() 
    {
        // handle clean up here ...
        //std::cout << "~Context[" << this << "]" << std::flush << std::endl;    
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

    void releaseContext(Context* addr)
    {
        std::lock_guard<std::mutex> guard(mtx);
        std::vector<Context*>::iterator mit;
        for (mit = context.begin(); mit != context.end();) {
            if (*mit == addr) {
                delete addr;
                mit = context.erase(mit);
                return;
            } else {
                mit++;
            }
        }
    }
};

#ifdef __cplusplus
extern "C" {
#endif

MODULE_API
int idpass_api_add_certificates(void* self,
                                 unsigned char** certificates,
                                 int* len,
                                 int ncertificates)
{
    Context* context = (Context*)self;
    int n;

    std::vector<Cert> chain;

    for (int i = 0; i < ncertificates; i++) {
        n = len[i];
        Cert cert;
        bool flag = cert.fromBuffer(certificates[i], n);
        if (flag && cert.hasValidSignature()) {
            chain.push_back(cert);
        }
    }

    if (chain.size() > 0 && context->verify_chain(chain)) {
        context->intermed_certificates = chain;
        return 0; // no errors
    }

    return 1;
}

//=============    
// Description:
// card_encryption_key : used to encrypt the card data
// card_signature_key  : used to sign the IDPassCard in the SignedIDPassCard object
// verification_keys   : list of trusted signer public keys
MODULE_API void* idpass_api_init(unsigned char* card_encryption_key,
                                 int card_encryption_key_len,
                                 unsigned char* card_signature_key,
                                 int card_signature_key_len,
                                 unsigned char* verification_keys,
                                 int verification_keys_len,
                                 unsigned char** certificates,
                                 int* len, // 160 each
                                 int ncertificates)
{
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

    if (!helper::is_valid_ed25519_key(card_signature_key)) {
        return nullptr; 
    }

    Context* context = M::newContext();

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

    context->facediff_half = DEFAULT_FACEDIFF_HALF;
    context->facediff_full = DEFAULT_FACEDIFF_FULL;
    context->fdimension = false; // defaults to 64/2
    context->qrcode_ecc = ECC_MEDIUM;
    std::memset(context->acl, 0x00, sizeof context->acl); // default all fields priv

    if (certificates && ncertificates > 0) {
        for (int i = 0; i < ncertificates; i++) {
            int n = len[i]; // 160 

            Cert cert;
            bool flag = cert.fromBuffer(certificates[i], n);

            if (flag && cert.hasValidSignature() && cert.isRootCA()) {
                context->root_certificates.push_back(cert);
            } else {
                M::releaseContext(context);
                return nullptr;
            }
        }
    }

    return static_cast<void*>(context);
}

MODULE_API
void idpass_api_freemem(void* self, void* buf)
{
    Context* context = (Context*)self;
    if (!context->ReleaseByteArray(buf)) {
        if (context == buf) {
            M::releaseContext(context);
        }
    }
}

/***********
Description:
Format is: nonce header + encrypted bytes*/
MODULE_API unsigned char*
idpass_api_create_card_with_face(void* self,
                                 int* outlen,
                                 const char* surname,
                                 const char* given_name,
                                 unsigned char* date_of_birth,
                                 int date_of_birth_len,
                                 const char* place_of_birth,
                                 const char* pin,
                                 char* photo,
                                 int photo_len,
                                 unsigned char* pub_extras_buf,
                                 int pub_extras_buf_len,
                                 unsigned char* priv_extras_buf,
                                 int priv_extras_buf_len)
{
    Context* context = (Context*)self;
    *outlen = 0;
    unsigned long int epochSeconds = std::time(nullptr);
    float faceArray[128];

    if (dlib_api::computeface128d(photo, photo_len, faceArray) != 1) {
        LOGI("idpass_api_create_card_with_face: fail");
        return nullptr;
    }

    ////////////////////////////////////////////////////////
    //////// card signer public key ///////////////////////
    unsigned char card_signerPublicKey[crypto_sign_PUBLICKEYBYTES];
    if (!context->intermed_certificates.empty()) {
        Cert c = context->intermed_certificates.back();
        std::memcpy(card_signerPublicKey, c.pubkey, 32);
    } else {
        crypto_sign_ed25519_sk_to_pk(card_signerPublicKey,
                                     context->signatureKey.data());
    }

    //////////////////////////
    // populate date of birth
    idpass::Date dob;
    if (date_of_birth && date_of_birth_len > 0) {
        dob.ParseFromArray(date_of_birth, date_of_birth_len);
    }

    //////////////////////////
    // populate user's access
    idpass::CardAccess access;
    access.set_pin(pin);

    if (context->fdimension) {
        unsigned char fdim_full[128 * 4];
        bin16::f4_to_f4b(faceArray, 128, fdim_full);
        access.set_face(fdim_full, sizeof fdim_full);
    } else {
        unsigned char fdim_half[64 * 2];
        bin16::f4_to_f2b(faceArray, 64, fdim_half);
        access.set_face(fdim_half, sizeof fdim_half);
    }

    ///////////////////////////////////////
    // populate private and public details
    idpass::CardDetails privDetails;
    idpass::CardDetails pubDetails;

    unsigned char acl = context->acl[0];

    if (acl & ACL_SURNAME) pubDetails.set_surname(surname);
    else privDetails.set_surname(surname);

    if (acl & ACL_GIVENNAME) pubDetails.set_givenname(given_name);
    else privDetails.set_givenname(given_name);

    if (acl & ACL_PLACEOFBIRTH) pubDetails.set_placeofbirth(place_of_birth);
    else privDetails.set_placeofbirth(place_of_birth);

    if (acl & ACL_CREATEDAT) pubDetails.set_createdat(epochSeconds);
    else privDetails.set_createdat(epochSeconds);

    if (dob.ByteSizeLong() > 0) {
        if (acl & ACL_DATEOFBIRTH)
            pubDetails.mutable_dateofbirth()->CopyFrom(dob);
        else
            privDetails.mutable_dateofbirth()->CopyFrom(dob);
    }

    idpass::Pair* kv = nullptr;

    idpass::Dictionary pubExtras;
    if (pub_extras_buf && pub_extras_buf_len > 0) {
        if (pubExtras.ParseFromArray(pub_extras_buf, pub_extras_buf_len)) {
            for (auto extra : pubExtras.pairs()) {
                kv = pubDetails.add_extra();
                kv->set_key(extra.key());
                kv->set_value(extra.value());
            }
        }
    }

    idpass::Dictionary privExtras;
    if (priv_extras_buf && priv_extras_buf_len > 0) {
        if (privExtras.ParseFromArray(priv_extras_buf, priv_extras_buf_len)) {
            for (auto extra : privExtras.pairs()) {
                kv = privDetails.add_extra();
                kv->set_key(extra.key());
                kv->set_value(extra.value());
            }
        }
    }

    idpass::PublicSignedIDPassCard publicRegion;
    if (pubDetails.ByteSizeLong() > 0) {
        publicRegion.mutable_details()->CopyFrom(pubDetails);
    }

     //////////////////////////////////////
    // generate user's unique ed25519 key
    unsigned char user_ed25519PubKey[crypto_sign_PUBLICKEYBYTES];   
    unsigned char user_ed25519PrivKey[crypto_sign_SECRETKEYBYTES]; 
    crypto_sign_keypair(user_ed25519PubKey, user_ed25519PrivKey);

     /////////////////
    // assemble ecard
    // IDPassCard: [access, details, encryptionKey]
    idpass::IDPassCard ecard;
    ecard.mutable_access()->CopyFrom(access);
    if (privDetails.ByteSizeLong() > 0) {
        ecard.mutable_details()->CopyFrom(privDetails);
    }
    ecard.set_encryptionkey(user_ed25519PrivKey, crypto_sign_SECRETKEYBYTES);

    idpass::SignedIDPassCard privateRegion;
    privateRegion.mutable_card()->CopyFrom(ecard);

    int privateRegionEncrypted_len = 0;
    std::vector<unsigned char> privateRegionEncrypted;
    privateRegionEncrypted_len = helper::encrypt_object(
        privateRegion, context->encryptionKey.data(), privateRegionEncrypted);

     ////////////////////////////////////////////////////////////
    // concatinate privateRegion and publicRegion (in this order) 
    // into a blob and then signed this blob
    std::vector<unsigned char> blob_privateRegion;
    std::vector<unsigned char> blob_publicRegion;
    std::vector<unsigned char> priv_pub_blob;
    unsigned char priv_pub_blob_signature[crypto_sign_BYTES];

    helper::serialize(privateRegion, blob_privateRegion);
    helper::serialize(publicRegion, blob_publicRegion);
    std::copy(blob_privateRegion.data(), blob_privateRegion.data() + blob_privateRegion.size(), std::back_inserter(priv_pub_blob));
    std::copy(blob_publicRegion.data(), blob_publicRegion.data() + blob_publicRegion.size(), std::back_inserter(priv_pub_blob));
    helper::sign_object(priv_pub_blob, context->signatureKey.data(), priv_pub_blob_signature);

     ///////////////////////////////
    // assemble final output object
    idpass::IDPassCards idpassCards;
    idpassCards.set_signature(priv_pub_blob_signature, crypto_sign_BYTES);
    idpassCards.set_signerpublickey(card_signerPublicKey, sizeof card_signerPublicKey);
    idpassCards.set_encryptedcard(privateRegionEncrypted.data(), privateRegionEncrypted_len);
    if (publicRegion.ByteSizeLong() > 0) {
        idpassCards.mutable_publiccard()->CopyFrom(publicRegion);
    }

     ///////////////////////////////////////////////////////////////////
    // now attach certificate chain if any into the final output object
    if (!context->intermed_certificates.empty()) {
        Cert* pcert = &context->intermed_certificates.back();
        do {
            idpass::Certificate *c = idpassCards.add_certificates();
            c->set_pubkey(pcert->pubkey, 32);
            c->set_signature(pcert->signature, 64);
            c->set_issuerkey(pcert->issuerkey, 32);
            if (pcert->isRootCA()) {
                break;
            }
            pcert = pcert->getIssuer(context->intermed_certificates, context->root_certificates);
        } while (pcert);
    }

     ////////////////////////////////////////////////////////
    // finally, serialiaze final output object as byte[] and
    // return it
    int buf_len = idpassCards.ByteSizeLong();
    unsigned char* buf = context->NewByteArray(buf_len);

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
    *outlen = 0;

    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->encryptionKey.data(),
                             context->signatureKey.data(),
                             context->verificationKeys,
                             card)) {
        return nullptr;
    }

    idpass::CardAccess access = card.access();
    double face_diff = helper::computeFaceDiff(photo, photo_len, access.face());
    double threshold = access.face().length() == 128 * 4 ? context->facediff_full :
                                                       context->facediff_half;
    if (face_diff <= threshold) {
        idpass::CardDetails details = card.details();
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
    *outlen = 0;

    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->encryptionKey.data(),
                             context->signatureKey.data(),
                             context->verificationKeys,
                             card)) {
        return nullptr;
    }

    idpass::CardAccess access = card.access();

    if (access.pin().compare(pin) == 0) {
        idpass::CardDetails details = card.details();
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
    *outlen = 0;

    unsigned char* ciphertext = nullptr;
    unsigned long long ciphertext_len = 0;

    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->encryptionKey.data(),
                             context->signatureKey.data(),
                             context->verificationKeys,
                             card)) {
        return nullptr;
    }

    // convert ed25519 to curve25519 and use curve25519 for encryption
    const unsigned char* ed25519_skpk
        = (const unsigned char*)card.encryptionkey().data();

    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];

    std::memcpy(
        ed25519_pk,
        ed25519_skpk + crypto_sign_ed25519_PUBLICKEYBYTES,
        crypto_sign_ed25519_PUBLICKEYBYTES);

    unsigned char x25519_pk[crypto_scalarmult_curve25519_BYTES]; // 32
    unsigned char x25519_sk[crypto_scalarmult_curve25519_BYTES]; // 32

    int ret = crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk);
    ret = crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_skpk);

    ///////////////////////////////////////////////////////////////////////////
    ciphertext_len = crypto_box_MACBYTES + data_len; // 16+
    ciphertext = new unsigned char[ciphertext_len];

    unsigned char nonce[crypto_box_NONCEBYTES]; // 24
    randombytes_buf(nonce, sizeof nonce);

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

MODULE_API
unsigned char* idpass_api_decrypt_with_card(void* self,
                                            int* outlen,
                                            unsigned char* encrypted,
                                            int encrypted_len,
                                            unsigned char* card_skpk,
                                            int skpk_len)
{
    Context* context = (Context*)self;
    int len = encrypted_len - crypto_box_NONCEBYTES - crypto_box_MACBYTES;
    *outlen = 0;
    if (len <= 0) {
        return nullptr;
    }

    unsigned char* plaintext = context->NewByteArray(len);
    unsigned char nonce[crypto_box_NONCEBYTES];
    std::memcpy(nonce, encrypted, sizeof nonce);

    unsigned long long ciphertext_len = encrypted_len - crypto_box_NONCEBYTES;
    unsigned char* ciphertext = new unsigned char[ciphertext_len];
    std::memcpy(ciphertext, encrypted + crypto_box_NONCEBYTES, ciphertext_len);

    unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
    unsigned char privkey[crypto_box_SECRETKEYBYTES];

    unsigned char card_pk[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_ed25519_sk_to_pk(card_pk, card_skpk);
    int ret;
    ret = crypto_sign_ed25519_pk_to_curve25519(pubkey, card_pk);
    crypto_sign_ed25519_sk_to_curve25519(privkey, card_skpk);

    // decrypt ciphertext to plaintext
    if (crypto_box_open_easy(
        plaintext,
        ciphertext,
        ciphertext_len,
        nonce,
        pubkey,
        privkey)
    != 0) {
        delete[] ciphertext;
        context->ReleaseByteArray(plaintext);
        return nullptr;
    }

    delete[] ciphertext;
    *outlen = len;
    return plaintext;
}

MODULE_API
int idpass_api_generate_encryption_key(
    unsigned char* key, int key_len)
{
    if (key_len != crypto_aead_chacha20poly1305_IETF_KEYBYTES) {
        return 1;
    }

    crypto_aead_chacha20poly1305_keygen(key);
    return 0;
}

MODULE_API
int idpass_api_generate_secret_signature_key(
    unsigned char *sig_skpk, int sig_skpk_len)
{
    if (sig_skpk_len != crypto_sign_SECRETKEYBYTES) {
        return 1;
    }

    unsigned char sig_pk[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_keypair(sig_pk, sig_skpk);
    return 0;
}

MODULE_API
int idpass_api_card_decrypt(void* self,
                            unsigned char* ecard_buf,
                            int *ecard_buf_len,
                            unsigned char *key,
                            int key_len)
{
    Context* context = (Context*)self;

    if (key_len != crypto_aead_chacha20poly1305_IETF_KEYBYTES ||
        key == nullptr ) 
    {
        return 1;
    }

    unsigned long long decrypted_len;
    unsigned char* decrypted
        = new unsigned char[*ecard_buf_len
                            - crypto_aead_chacha20poly1305_IETF_NPUBBYTES];

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    std::memcpy(nonce, ecard_buf, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted,
            &decrypted_len,
            NULL, // always
            ecard_buf + crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
            *ecard_buf_len - crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
            NULL,
            0,
            nonce,
            key)
    != 0) {
        return 2;
    }

    *ecard_buf_len = (int)decrypted_len;
    std::memcpy(ecard_buf, decrypted, decrypted_len);
    delete[] decrypted;
    return 0;
}

MODULE_API
int idpass_api_verify_with_card(void* self,
                                unsigned char* msg,
                                int msg_len,
                                unsigned char* signature,
                                int signature_len,
                                unsigned char* pubkey,
                                int pubkey_len)
{
    Context* context = (Context*)self;

    if (pubkey_len != crypto_sign_PUBLICKEYBYTES ||
        pubkey == nullptr ||
        signature_len != crypto_sign_BYTES ||
        signature == nullptr ||
        msg == nullptr ||
        msg_len <= 0)
    {
        return 1;
    }

    int status = crypto_sign_verify_detached(signature, msg, msg_len, pubkey);
    return status;
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
    *outlen = 0;

    unsigned char* signature = nullptr;

    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->encryptionKey.data(),
                             context->signatureKey.data(),
                             context->verificationKeys,
                             card)) {
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
            (const unsigned char*)card.encryptionkey().data())
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

MODULE_API unsigned char* idpass_api_qrpixel2(void* self, int* outlen,
                                             const unsigned char* data,
                                             int data_len,
                                             int* qrsize)
{
    Context* context = (Context*)self;
    int buf_len = 0;
    *outlen = 0;

    unsigned char* buf = qrcode_getpixel(
        data, data_len, qrsize, &buf_len, context->qrcode_ecc);

    if (buf == nullptr) {
        LOGI("idpass_api_qrpixel2: error");
        return nullptr;
    }

    // re-allocate & copy into our manage area
    unsigned char* pixel = context->NewByteArray(buf_len);
    std::memcpy(pixel, buf, buf_len);
    *outlen = buf_len;
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
        case IOCTL_SET_FACEDIFF: { // set new facediff value
            float facediff;
            bin16::f4b_to_f4(iobuf + 1, iobuf_len - 1, &facediff);
            if (context->fdimension) {
                context->facediff_full = facediff;
            } else {
                context->facediff_half = facediff;
            }
        } break;

        case IOCTL_GET_FACEDIFF: { // get current facediff value
            if (context->fdimension) {
                bin16::f4_to_f4b(&context->facediff_full, 1, iobuf + 1);
            } else {
                bin16::f4_to_f4b(&context->facediff_half, 1, iobuf + 1);
            }
        } break;

        case IOCTL_SET_FDIM: { // set fdimension flag
            if (iobuf[1] == 0x00) {
                context->fdimension = false;
            } else if (iobuf[1] == 0x01) {
                context->fdimension = true;
            }
        } break;             

        case IOCTL_GET_FDIM: { // get fdimension flag
            if (context->fdimension) {
                iobuf[1] = 0x01;
            } else {
                iobuf[1] = 0x00;
            }
        } break;             

        case IOCTL_SET_ECC: { // set QR Code ECC level
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

        case IOCTL_SET_ACL: {
            // TODO: Control which field goes to public or private
            // Make it more flexible later. For now, the next byte
            // is the ACL. The proper way, I think should follow
            // that of popular TLV 7bit and use the 8th bit to
            // describe the next bytes. In this way, when the
            // number of configurable bits increases can be better
            // managed.
            unsigned char acl = iobuf[1];
            context->acl[0] = acl;
        } break;
    }

    return nullptr;
}

MODULE_API int
idpass_api_face128d(void* self, char* photo, int photo_len, float* faceArray)
{
    Context* context = (Context*)self;
    return dlib_api::computeface128d(photo, photo_len, faceArray);
}

MODULE_API int idpass_api_face128dbuf(void* self,
                                      char* photo,
                                      int photo_len,
                                      unsigned char* buf)
{
    Context* context = (Context*)self;
    float f4[128];
    int face_count = dlib_api::computeface128d(photo, photo_len, f4);

    if (face_count == 1) {
        bin16::f4_to_f4b(f4, 128, buf);
    }

    return face_count;
}

MODULE_API
int idpass_api_face64d(void* self,
                       char* photo,
                       int photo_len,
                       float* facearray)
{
    Context* context = (Context*)self;
    float fdim[128];
    int facecount = dlib_api::computeface128d(photo, photo_len, fdim);
    bin16::f4_to_f2(fdim, 64, facearray);
    return facecount;
}

MODULE_API int idpass_api_face64dbuf(void* self,
                                     char* photo,
                                     int photo_len,
                                     unsigned char* buf)
{
    Context* context = (Context*)self;
    float f4[128];
    int face_count = dlib_api::computeface128d(photo, photo_len, f4);

    if (face_count == 1) {
        bin16::f4_to_f2b(f4, 64, buf);
    }

    return face_count;
}

MODULE_API
int idpass_api_compare_face_photo(void *self,
                          char* face1,
                          int face1_len,
                          char* face2,
                          int face2_len,
                          float *fdiff)
{
    Context* context = (Context*)self;

    if (face1 == nullptr ||
        face2 == nullptr ||
        face1_len == 0 ||
        face2_len == 0)
    {
        return 3; // invalid params
    }

    float result = 10.0;
    float face1Array[128];
    float face2Array[128];

    if (dlib_api::computeface128d((char*)face1, face1_len, face1Array) != 1) {
        return 1; // something wrong in face1
    }

    if (dlib_api::computeface128d((char*)face2, face2_len, face2Array) != 1) {
        return 2; // something wrong in face2
    }

    // convert vector representation based on fdim mode of calling context
    if (context->fdimension) {
        result = helper::euclidean_diff(face1Array, face2Array, 128);
    } else {
        float face1Array_half[64];
        float face2Array_half[64];
        bin16::f4_to_f2(face1Array, 64, face1Array_half);
        bin16::f4_to_f2(face2Array, 64, face2Array_half);
        result = helper::euclidean_diff(face1Array_half, face2Array_half, 64);
    }

    if (fdiff) {
        *fdiff = result;
    }

    return 0; // success or no error
}

MODULE_API
int idpass_api_compare_face_template(unsigned char* face1,
                                     int face1_len,
                                     unsigned char* face2,
                                     int face2_len,
                                     float *fdiff)
{
    float face1Array[128];
    float face2Array[128];
    int len = 0;

    if (face1_len == 128 * 4) {
        bin16::f4b_to_f4(face1, face1_len, face1Array);
        len = 128;
    } else if (face1_len == 64 * 2) {
        bin16::f2b_to_f4(face1, face1_len, face1Array);
        len = 64;
    } else {
        return 1;
    }

    if (face2_len == 128 * 4) {
        bin16::f4b_to_f4(face2, face2_len, face2Array);
        len = 128;
    } else if (face2_len == 64 * 2) {
        bin16::f2b_to_f4(face2, face2_len, face2Array);
        len = 64;
    } else {
        return 2; 
    }

    float result = helper::euclidean_diff(face1Array, face2Array, len);
    if (fdiff) {
        *fdiff = result; 
    }

    return 0;
}

MODULE_API
int idpass_api_generate_root_certificate(unsigned char* skpk,
                                         int skpk_len,
                                         unsigned char* buf,
                                         int buf_len)
{
    if (skpk_len != crypto_sign_SECRETKEYBYTES ||
        skpk == nullptr ||
        buf == nullptr ||
        buf_len != 160) {
        return 1;
    }

    unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_ed25519_sk_to_pk(pubkey, skpk);
    unsigned char signature[crypto_sign_BYTES]; // 64

    if (crypto_sign_detached(
        signature,
        nullptr,
        pubkey,
        sizeof pubkey,
        skpk)
    != 0) {
        return 2;
    }

    std::memcpy(buf, skpk, crypto_sign_SECRETKEYBYTES); // 64
    std::memcpy(buf + skpk_len, signature, crypto_sign_BYTES); // 64
    std::memcpy(buf + skpk_len + crypto_sign_BYTES, pubkey, crypto_sign_PUBLICKEYBYTES); // 32
    // total = 160

    return 0;
}

MODULE_API
int idpass_api_generate_child_certificate(unsigned char* parent_skpk,
                                          int parent_skpk_len,
                                          unsigned char* child_key,
                                          int child_key_len,
                                          unsigned char* buf,
                                          int buf_len)
{
    if (parent_skpk_len != crypto_sign_SECRETKEYBYTES ||
        parent_skpk == nullptr ||
        (child_key_len != crypto_sign_PUBLICKEYBYTES && child_key_len != crypto_sign_SECRETKEYBYTES) ||
        child_key == nullptr ||
        buf == nullptr ||
        (buf_len != 128 && buf_len != 160)) {
        return 1;
    }

    unsigned char issuerkey[crypto_sign_PUBLICKEYBYTES];
    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_ed25519_sk_to_pk(issuerkey, parent_skpk);

    if (child_key_len == crypto_sign_PUBLICKEYBYTES) {
        // sign the child's public key
        if (crypto_sign_detached(
            signature, nullptr, child_key, crypto_sign_PUBLICKEYBYTES, parent_skpk)
        != 0) {
            return 2;
        }

        std::memcpy(buf, child_key, crypto_sign_PUBLICKEYBYTES);
        std::memcpy( buf + crypto_sign_PUBLICKEYBYTES, signature, crypto_sign_BYTES);
        std::memcpy(buf + crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES, issuerkey, crypto_sign_PUBLICKEYBYTES);
    } else if (child_key_len == crypto_sign_SECRETKEYBYTES) {

        unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];
        crypto_sign_ed25519_sk_to_pk(pubkey, child_key);

        if (crypto_sign_detached(
                signature, nullptr, pubkey, crypto_sign_PUBLICKEYBYTES, parent_skpk)
            != 0) {
            return 2;
        }

        std::memcpy(buf, child_key, crypto_sign_SECRETKEYBYTES);
        std::memcpy(buf + crypto_sign_SECRETKEYBYTES, signature, crypto_sign_BYTES);
        std::memcpy(buf + crypto_sign_SECRETKEYBYTES + crypto_sign_BYTES, issuerkey, crypto_sign_PUBLICKEYBYTES);
    } else {
        return 3;
    }

    return 0;
}

MODULE_API
int idpass_api_add_revoked_key(unsigned char* pubkey, int pubkey_len)
{
    if (pubkey == nullptr || pubkey_len != crypto_sign_PUBLICKEYBYTES) {
        return 1;
    }

    std::lock_guard<std::mutex> guard(g_mutex);
    struct stat st;
    std::ofstream outfile(REVOKED_KEYS, std::ios::out | std::ios::binary | std::ios::app);
    outfile.write(reinterpret_cast<const char*>(pubkey), pubkey_len);
    outfile.close();

    return 0;
}

// Saves the QR Code encoding to a bitmap file
MODULE_API int idpass_api_saveToBitmap(void* self,
                                       unsigned char* data,
                                       int data_len,
                                       const char* bitmapfile)
{
    Context* context = (Context*)self;

    return qrcode_saveToBitmap(data, data_len, bitmapfile, context->qrcode_ecc);
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
