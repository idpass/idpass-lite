/*
 * Copyright (C) 2020 Newlogic Impact Lab Pte. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "idpass.h"

#include "CCertificate.h"
#include "bin16.h"
#include "dlibapi.h"
#include "dxtracker.h"
#include "helper.h"
#include "proto/api/api.pb.h"
#include "proto/idpasslite/idpasslite.pb.h"
#include "qrcode.h"
#include "sodium.h"

#include <array>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <iterator>
#include <jni.h>
#include <list>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <algorithm>

#ifdef ANDROID
#include <android/log.h>

#define LOGI(...) \
    ((void)__android_log_print(ANDROID_LOG_INFO, "idpass::idpass", __VA_ARGS__))
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

char dxtracker[] = DXTRACKER;

std::mutex g_mutex;
std::list<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>> g_revokedKeys;

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    static bool runonce = false;
    if (runonce) {
        return JNI_VERSION_1_6;
    }
    runonce = true;

    JNIEnv* env;

    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
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
        map_JNI(
            "org/idpass/lite/IDPassReader", &IDPASS_JNI[0], IDPASS_JNI_TLEN);
#endif
    } catch (...) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}

struct Context {
    std::mutex ctxMutex;
    std::mutex mtx;
    std::vector<std::vector<unsigned char>> m;

    api::KeySet m_keyset;

    std::vector<CCertificate> m_rootCerts;
    std::vector<CCertificate> m_intermedCerts;

    float facediff_half;
    float facediff_full;
    bool fdimension; // 128/4 if true else 64/2
    int qrcode_ecc;

    unsigned char acl[1];

    unsigned char* NewByteArray(int n)
    {
        if (n <= 0)
            return nullptr;
        std::lock_guard<std::mutex> guard(mtx);
        m.emplace_back(n);
        return m.back().data();
    }

    bool ReleaseByteArray(void* addr)
    {
        if (addr == nullptr)
            return false;
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

    bool verify_chain(idpass::IDPassCards& fullCard)
    {
        int n = fullCard.certificates_size();
        if (fullCard.certificates_size() > 0) {
            std::vector<CCertificate> chain;

            try {
                for (auto& c : fullCard.certificates()) {
                    CCertificate cer(c);
                    // context->m_intermedCerts.push_back(cer);
                    chain.push_back(cer);
                }
            } catch (std::exception& e) {
                return false;
            }

            if (chain.size() > 0 && verify_chain(chain)) {
                // m_intermedCerts = chain;
                return true;
            }

            return false;
        }

        return true;
    }

    bool verify_chain(std::vector<CCertificate>& chain)
    {
        auto in_root_certificates = [this](const CCertificate* c) {
            return std::find_if(m_rootCerts.begin(),
                                m_rootCerts.end(),
                                [&c](const CCertificate& m) -> bool {
                                    return std::memcmp(m.m_pk.data(),
                                                       c->m_pk.data(),
                                                       32)
                                           == 0;
                                })
                   != m_rootCerts.end();
        };

        if (chain.size() == 0) {
            return false;
        }

        CCertificate* pCert = &chain.back();
        unsigned char* startkey = pCert->m_pk.data();

        while (pCert != nullptr) {
            if (pCert->hasValidSignature()) {
                if (helper::isRevoked(g_revokedKeys, pCert->m_pk.data(), 32)) {
                    return false;
                }
                if (!pCert->isSelfSigned()) {
                    pCert = pCert->getIssuer(chain, m_rootCerts);
                    if (pCert == nullptr
                        || std::memcmp(
                               pCert->m_pk.data(), startkey, 32)
                               == 0) {
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
        // Choosing the more secure option such that
        // no certificate claim is asserted if either the 
        // card or the reader has no attached or 
        // configured certificate(s).
        return false;
    }

    Context()
    {
    }

    ~Context()
    {
    }
};

namespace M
{
std::mutex mtx;
std::vector<Context*> context;
std::mutex m_mtx;
std::vector<std::vector<unsigned char>> m_m;

Context* newContext()
{
    std::lock_guard<std::mutex> guard(mtx);
    Context* c = new Context;
    context.push_back(c);
    return c;
}

void releaseContext(Context* addr)
{
    if (addr == nullptr)
        return;
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

unsigned char* NewByteArray(int n)
{
    if (n <= 0)
        return nullptr;
    std::lock_guard<std::mutex> guard(m_mtx);
    m_m.emplace_back(n);
    return m_m.back().data();
}

bool ReleaseByteArray(void* addr)
{
    if (addr == nullptr)
        return false;
    std::lock_guard<std::mutex> guard(m_mtx);
    std::vector<std::vector<unsigned char>>::iterator mit;
    for (mit = m_m.begin(); mit != m_m.end();) {
        if (mit->data() == addr) {
            mit = m_m.erase(mit);
            return true;
        } else {
            mit++;
        }
    }
    return false;
}
};

#ifdef __cplusplus
extern "C" {
#endif

/**
* Verifies the fullcard's attached certificate against the root
* certificate configured in the context. Returns 0 if the
* card has no attached certificates, otherwise it returns 
* the count of validated certificates. 
* Returns < 0 if the attached certificates fails to validate, or
* the card signature does not verify.
*
* @param self Calling context
* @param certs_buf The fullcard bytes content
* @param certs_buf_len The bytes length of certs_buf
@ @return int Either -1, 0, or > 0
*/

// The idpass_lite_verify_certificate function returns either
// < 0, 0 or > 0 integer.
//
// The 0 means the QR code ID card has no attached certificates
// but nevertheless the card's signature is verified against
// the context's ed25519 private key
// Any error conditions either in certificate validation
// or QR code ID card signature verification shall return
// negative number. In summary:
//
// 0    means the card has no attached certificate and
//      the signature is verified against caller context
// 2    means the card has 2 attached certificates and the signature
//      is verified against the caller context(or leaf cert)
// < 0  means an error either in certificate validation or
//      in signature verification

MODULE_API
int idpass_lite_verify_certificate(void* self,
                                   unsigned char* fullcard,
                                   int fullcard_len)
{
    Context* context = (Context*)self;

    if (fullcard == nullptr || fullcard_len <= 0 || self == nullptr) {
        return -1;
    }

    idpass::IDPassCards cards;
    if (!cards.ParseFromArray(fullcard, fullcard_len)) {
        return -2;
    }

    int count = cards.certificates_size();
    if (count > 0) {
        if (!context->verify_chain(cards)) {
            return -3;
        }
    } else {
        return -6;
    }

    // check if leaf cert signature is valid against blob
    idpass::PublicSignedIDPassCard pubCard = cards.publiccard();
    std::vector<unsigned char> pubcardbuf(pubCard.ByteSizeLong());
    pubCard.SerializeToArray(pubcardbuf.data(), pubcardbuf.size());

    std::vector<unsigned char> card_blob;

    std::copy(cards.encryptedcard().begin(),
              cards.encryptedcard().end(),
              std::back_inserter(card_blob));

    std::copy(pubcardbuf.begin(),
              pubcardbuf.end(),
              std::back_inserter(card_blob));

    if (crypto_sign_verify_detached(
            (const unsigned char*)cards.signature().data(),
            card_blob.data(),
            card_blob.size(),
            (const unsigned char*)cards.signerpublickey().data())
    != 0) 
    {
        return -5;
    } 
    /*

    bool found = false;
    for (auto& pub : context->m_keyset.verificationkeys()) {
        if (pub.typ() == api::byteArray_Typ_ED25519PUBKEY) {
            if (std::memcmp(pub.val().data(), cards.signerpublickey().data(), 32) == 0) {
                found = true;
                break;
            }
        }
    }

    if (!found) {
        return -6;
    }
    */

    // If the card was issued with no attached certificate chain
    // then count is 0. And the card signature is still verified
    // against the reader's keyset. The interpretation of this
    // is relegated to Java. I find that the return values of:
    // <0, 0, >0 is the most compact return value to convey
    // the information.
    // 
    // The idpass_lite_verify_certificate is to be merged
    // into idpass_lite_verify_card_signature soon.

    return count;
}

MODULE_API
int idpass_lite_verify_card_signature(void* self,
                                      unsigned char* fullcard,
                                      int fullcard_len, int skipcheckcert)
{
    if (self == nullptr || fullcard == nullptr
        ||fullcard_len <= 0 ) {
        return 1;
    }
    Context* context = (Context*)self;

    idpass::IDPassCards fullCard;

    if (!fullCard.ParseFromArray(fullcard, fullcard_len)) {
        return 2;
    }

    idpass::PublicSignedIDPassCard pubCard = fullCard.publiccard();
    std::vector<unsigned char> pubcardbuf(pubCard.ByteSizeLong());
    pubCard.SerializeToArray(pubcardbuf.data(), pubcardbuf.size());

    std::vector<unsigned char> card_blob;

    std::copy(fullCard.encryptedcard().begin(),
              fullCard.encryptedcard().end(),
              std::back_inserter(card_blob));

    std::copy(pubcardbuf.begin(),
              pubcardbuf.end(),
              std::back_inserter(card_blob));

    if (crypto_sign_verify_detached(
            (const unsigned char*)fullCard.signature().data(),
            card_blob.data(),
            card_blob.size(),
            (const unsigned char*)fullCard.signerpublickey().data())
    != 0) 
    {
        return 3;
    } 

    if (skipcheckcert == 1) {
        // The card signature verifies alright, but we still need to
        // check if the card's signer public key is in our context
        // verification list, ie Context::m_keyset::verificationKeys
        bool found = false;
        for (auto& pub : context->m_keyset.verificationkeys()) {
            if (pub.typ() == api::byteArray_Typ_ED25519PUBKEY) {
                if (std::memcmp(
                        pub.val().data(), fullCard.signerpublickey().data(), 32)
                    == 0) {
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            return 4;
        }

        return 0;
    }
    

#if 1
    // Temporarily comment out to clearly sort out the Java API.
    // My plan is to combine the verify_card_certificate and
    // verify_card_signature into the singular JNI function
    // verify_card_signature with additional 
    // boolean skipCertificateVerification parameter.
    // Rationale is that the verify_card_signature is the superset
    // wherein the verify_card_certificate is a subset. The
    // verify_card_certificate implies the claim of its leaf
    // cert about the card signature, without
    // which, the entire chain is meaningless even if the chain validates
    // to a root anchor. Hence, verify_card_signature is the root
    // essence and the additional boolean flag is used to further
    // check the card's certificate chain.
    if (!context->verify_chain(fullCard)) {
        return 1;
    }
#endif
    return 0;
}


/**
* Adds intermediate certificates into the calling context.
* Cards created, thereafter, shall attached these certificates
* into the issued QR code ID. Intermediate certificates can only
* be added into the calling context having initialized with root certificates.
*
* @param self Calling context
* @param certs_buf The list of intermediate certificates
* @param certs_buf_len The bytes length of certs_buf
* @return int Returns 0 on success
*/

MODULE_API
int idpass_lite_add_certificates(void* self,
                                 unsigned char* certs_buf,
                                 int certs_buf_len)
{
    if (self == nullptr || certs_buf == nullptr || 
        certs_buf_len <= 0) {
        return 1; 
    }
    Context* context = (Context*)self;

    if (context->m_rootCerts.size() == 0) {
        return 1; // cannot add intermed certs 
        // without rootcerts set
    }

    api::Certificates intermedCerts;
    if (!intermedCerts.ParseFromArray(certs_buf, certs_buf_len)) {
        return 2;
    }

    std::vector<CCertificate> chain;

    try {
        for (auto& c : intermedCerts.cert()) {
            CCertificate cer(c);
            // context->m_intermedCerts.push_back(cer);
            chain.push_back(cer);
        }
    } catch (std::exception& e) {
        return 3;
    }

    if (chain.size() > 0 && context->verify_chain(chain)) {
        context->m_intermedCerts = chain;
        return 0; // no errors
    }

    return 1;
}

/**
* The main initilizationfunction of the library.
*
* @param keyset_buf The cryptographic key settings for the context.
* @param keyset_buf_len Length of bytes of keyset_buf
* @param rootcerts_buf The root certificates for the context.
* @param rootcerts_buf_len The length of bytes of rootcerts_buf
* @return void* Returns the library context.
*/

MODULE_API
void* idpass_lite_init(unsigned char* keyset_buf,
                       int keyset_buf_len,
                       unsigned char* rootcerts_buf,
                       int rootcerts_buf_len)
{
    if (!keyset_buf || keyset_buf_len <= 0
        ) {
        LOGI("invalid params");
        return nullptr;
    }

    api::KeySet cryptoKeys;
    api::Certificates rootCerts;

    if (!cryptoKeys.ParseFromArray(keyset_buf, keyset_buf_len)
        ) {
        LOGI("invalid params deserialization");
        return nullptr;
    }

    if (rootcerts_buf && rootcerts_buf_len > 0) {
        if (!rootCerts.ParseFromArray(rootcerts_buf, rootcerts_buf_len)) {
            return nullptr; 
        }
    }

    if (!helper::is_valid(cryptoKeys)) {
        return nullptr;
    }

    if (sodium_init() < 0) {
        LOGI("sodium_init failed");
        return nullptr;
    }

    Context* context = M::newContext();

    try {
        for (auto& c : rootCerts.cert()) {
            CCertificate cer(c);
            if (!cer.isSelfSigned()) {
                return nullptr;
            }
            /*if (!cer.hasPrivateKey()) {
                return nullptr;
            }*/
            context->m_rootCerts.push_back(cer);
        }
    } catch (std::exception& e) {
        return nullptr;
    }

    context->m_keyset = cryptoKeys;

    context->facediff_half = DEFAULT_FACEDIFF_HALF;
    context->facediff_full = DEFAULT_FACEDIFF_FULL;
    context->fdimension = false; // defaults to 64/2
    context->qrcode_ecc = ECC_MEDIUM;
    std::memset(
        context->acl, 0x00, sizeof context->acl); // default all fields priv

    return static_cast<void*>(context);
}

/**
* Explicitely frees up memory blocks returned by context.
*
* @param self Calling context
* @param buf Memory address returned by context
*/

MODULE_API
void idpass_lite_freemem(void* self, void* buf)
{
    if (buf == nullptr)
        return;

    if (self == nullptr) {
        M::ReleaseByteArray(buf); 
    } else {
        Context* context = (Context*)self;
        if (!context->ReleaseByteArray(buf)) {
            if (context == buf) {
                M::releaseContext(context);
            }
        }
    }
}

/**
* Returns a QR code ID of a registered identity.
*
* @param self Calling context
* @param outlen Bytes length of returned bytes
* @ident_buf The personal details of the registered identity
* @ident_buf_len Bytes length of ident_buf
* @return Returns an encrypted QR code ID
*/

MODULE_API
unsigned char* idpass_lite_create_card_with_face(void* self,
                                                 int* outlen,
                                                 unsigned char* ident_buf,
                                                 int ident_buf_len)
{
    if (self == nullptr || outlen == nullptr || ident_buf == nullptr
        || ident_buf_len <= 0) {
        return nullptr;
    }

    Context* context = (Context*)self;
    *outlen = 0;
#ifdef ALWAYS
    unsigned long int epochSeconds = 12345;
#else
    unsigned long int epochSeconds = std::time(nullptr);
#endif
    float faceArray[128];

    api::Ident ident;
    if (!ident.ParseFromArray(ident_buf, ident_buf_len)) {
        return nullptr;
    }

    if (dlib_api::computeface128d(
            ident.photo().data(), ident.photo().size(), faceArray)
        != 1) {
        LOGI("idpass_api_create_card_with_face: fail");
        return nullptr;
    }

    ////////////////////////////////////////////////////////
    //////// card signer public key ///////////////////////
    unsigned char card_signerPublicKey[crypto_sign_PUBLICKEYBYTES];

    int n = context->m_intermedCerts.size();
    if (n > 0) {
        CCertificate cc = context->m_intermedCerts.back();
        std::memcpy(card_signerPublicKey, cc.m_pk.data(), 32);
    } else {
        crypto_sign_ed25519_sk_to_pk(
            card_signerPublicKey,
            reinterpret_cast<const unsigned char*>(
                context->m_keyset.signaturekey().data()));
    }

    //////////////////////////
    // populate date of birth
    idpass::Date dob;
    dob.set_year(ident.dateofbirth().year());
    dob.set_month(ident.dateofbirth().month());
    dob.set_day(ident.dateofbirth().day());

    //////////////////////////
    // populate user's access
    idpass::CardAccess access;
    access.set_pin(ident.pin().data());

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

    if (acl & ACL_SURNAME)
        pubDetails.set_surname(ident.surname().data());
    else
        privDetails.set_surname(ident.surname().data());

    if (acl & ACL_GIVENNAME)
        pubDetails.set_givenname(ident.givenname().data());
    else
        privDetails.set_givenname(ident.givenname().data());

    if (acl & ACL_PLACEOFBIRTH)
        pubDetails.set_placeofbirth(ident.placeofbirth().data());
    else
        privDetails.set_placeofbirth(ident.placeofbirth().data());

    if (acl & ACL_CREATEDAT)
        pubDetails.set_createdat(epochSeconds);
    else
        privDetails.set_createdat(epochSeconds);

    if (acl & ACL_DATEOFBIRTH)
        pubDetails.mutable_dateofbirth()->CopyFrom(dob);
    else
        privDetails.mutable_dateofbirth()->CopyFrom(dob);

    idpass::Pair* kv = nullptr;

    idpass::Dictionary pubExtras;
    if (ident.pubextra_size() > 0) {
        for (auto& p : ident.pubextra()) {
            kv = pubDetails.add_extra();
            kv->set_key(p.key());
            kv->set_value(p.value());
        }
    }

    idpass::Dictionary privExtras;
    if (ident.privextra_size() > 0) {
        for (auto& p : ident.privextra()) {
            kv = privDetails.add_extra();
            kv->set_key(p.key());
            kv->set_value(p.value());
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
#ifdef ALWAYS
    unsigned char sk_always[]
        = {0x2d, 0x52, 0xf8, 0x6a, 0xaa, 0x4d, 0x62, 0xfc, 0xab, 0x4d, 0xb0,
           0x0a, 0x21, 0x1a, 0x12, 0x60, 0xf8, 0x17, 0xc5, 0xf2, 0xba, 0xb7,
           0x3e, 0xfe, 0xd6, 0x36, 0x07, 0xbc, 0x9d, 0xb3, 0x96, 0xee,
           0x57, 0xc6, 0x33, 0x09, 0xfa, 0xc2, 0x1b, 0x60, 0x04, 0x76, 0x4e,
           0xf6, 0xf7, 0xc6, 0x2f, 0x28, 0xcf, 0x63, 0x40, 0xbe, 0x13, 0x10,
           0x6e, 0x80, 0xed, 0x70, 0x41, 0x8f, 0xa1, 0xb9, 0x27, 0xb4}; // 64
    
    std::memcpy(user_ed25519PrivKey, sk_always, 64);
    crypto_sign_ed25519_sk_to_pk(user_ed25519PubKey, user_ed25519PrivKey);
#else
    crypto_sign_keypair(user_ed25519PubKey, user_ed25519PrivKey);
#endif
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

    privateRegionEncrypted_len
        = helper::encrypt_object(privateRegion,
                                 context->m_keyset.encryptionkey().data(),
                                 privateRegionEncrypted);

    ////////////////////////////////////////////////////////////
    // concatinate privateRegion and publicRegion (in this order)
    // into a blob and then signed this blob
    //std::vector<unsigned char> blob_privateRegion;
    std::vector<unsigned char> blob_publicRegion;
    std::vector<unsigned char> card_blob;
    unsigned char card_blob_sig[crypto_sign_BYTES];

    //helper::serialize(privateRegion, blob_privateRegion);
    helper::serialize(publicRegion, blob_publicRegion);
    std::copy(privateRegionEncrypted.begin(),
              privateRegionEncrypted.end(),
              std::back_inserter(card_blob));
    std::copy(blob_publicRegion.begin(),
              blob_publicRegion.end(),
              std::back_inserter(card_blob));

    helper::sign_object(card_blob,
                        context->m_keyset.signaturekey().data(),
                        card_blob_sig);

    ///////////////////////////////
    // assemble final output object
    idpass::IDPassCards idpassCards;
    idpassCards.set_signature(card_blob_sig, crypto_sign_BYTES);
    idpassCards.set_signerpublickey(card_signerPublicKey,
                                    sizeof card_signerPublicKey);
    idpassCards.set_encryptedcard(privateRegionEncrypted.data(),
                                  privateRegionEncrypted_len);
    if (publicRegion.ByteSizeLong() > 0) {
        idpassCards.mutable_publiccard()->CopyFrom(publicRegion);
    }

    ///////////////////////////////////////////////////////////////////
    // now attach certificate chain if any into the final output object
    n = context->m_intermedCerts.size();
    if (n > 0) {
        for (auto& cer : context->m_intermedCerts) {
            idpass::Certificate* c = idpassCards.add_certificates();
            c->set_pubkey(cer.m_pk.data(), 32);
            c->set_signature(cer.m_signature.data(), 64);
            c->set_issuerkey(cer.m_issuerkey.data(), 32);
            // TODO add check like before?
        }
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

/**
* Verify user's QR code ID against a matching photo.
*
* @param self Calling context
* @param *outlen Bytes length of returned bytes
* @param encrypted_card The user's QR code ID
* @param encrypted_card_len Bytes length of encrypted_card
* @param photo The ID owner's photo capture
* @param photo_len Length of bytes of photo
* @return Returns the user's CardDetails if there is facial match.
*/

// Returns CardDetails object if face matches
MODULE_API unsigned char*
idpass_lite_verify_card_with_face(void* self,
                                  int* outlen,
                                  unsigned char* encrypted_card,
                                  int encrypted_card_len,
                                  char* photo,
                                  int photo_len)
{
    if (self == nullptr || outlen == nullptr ||
        encrypted_card == nullptr || encrypted_card_len <= 0 
        || photo == nullptr || photo_len <= 0) 
    {
        return nullptr; 
    }
    Context* context = (Context*)self;
    *outlen = 0;

    idpass::IDPassCards cards;
    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->m_keyset,
                             card,
                             cards)) {
        return nullptr;
    }

    if (!context->verify_chain(cards)) {
        return nullptr;
    }

    idpass::CardAccess access = card.access();
    double face_diff = helper::computeFaceDiff(photo, photo_len, access.face());
    double threshold = access.face().length() == 128 * 4 ?
                           context->facediff_full :
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

/**
* Verify user's QR code ID against a matching pin.
*
* @param self Calling context
* @param *outlen Bytes length of returned bytes
* @param encrypted_card The user's QR code ID
* @param encrypted_card_len Bytes length of encrypted_card
* @param pin The ID owner's secret pin code
* @return Returns the user's CardDetails if there is pin match.
*/

MODULE_API unsigned char*
idpass_lite_verify_card_with_pin(void* self,
                                 int* outlen,
                                 unsigned char* encrypted_card,
                                 int encrypted_card_len,
                                 const char* pin)
{
    if (self == nullptr || outlen == nullptr ||
        encrypted_card == nullptr || encrypted_card_len <= 0 
        || pin == nullptr) {
        return nullptr; 
    }
    Context* context = (Context*)self;
    *outlen = 0;

    idpass::IDPassCards cards;
    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->m_keyset,
                             card,
                             cards)) {
        return nullptr;
    }

    if (!context->verify_chain(cards)) {
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

/**
* Encrypt data with user's QR code ID.
*
* @param self
* @param outlen Bytes length of encrypted data
* @param encrypted_card User's QR code ID.
* @param encrypted_card_len Bytes length of encrypted_card
* @param data The input data to be encrypted
* @param data_len Bytes length of data
* @return The encrypted data
*/

MODULE_API unsigned char*
idpass_lite_encrypt_with_card(void* self,
                              int* outlen,
                              unsigned char* encrypted_card,
                              int encrypted_card_len,
                              unsigned char* data,
                              int data_len)
{
    if (self == nullptr || outlen == nullptr ||
        encrypted_card == nullptr || encrypted_card_len <= 0 || 
        data == nullptr || data_len <= 0) 
    {
        return nullptr; 
    }
    Context* context = (Context*)self;
    *outlen = 0;

    unsigned char* ciphertext = nullptr;
    unsigned long long ciphertext_len = 0;

    idpass::IDPassCards cards;
    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->m_keyset,
                             card,
                             cards)) {
        return nullptr;
    }

    if (!context->verify_chain(cards)) {
        return nullptr;
    }

    // convert ed25519 to curve25519 and use curve25519 for encryption
    const unsigned char* ed25519_skpk
        = (const unsigned char*)card.encryptionkey().data();

    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];

    std::memcpy(ed25519_pk,
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
    if (crypto_box_easy(ciphertext, data, data_len, nonce, x25519_pk, x25519_sk)
        != 0) {
        LOGI("crypto_box_easy: error");
        delete[] ciphertext;
        return nullptr;
    }
    ///////////////////////////////////////////////////////////////////////////

    unsigned char* nonce_plus_ciphertext
        = context->NewByteArray(sizeof nonce + ciphertext_len);

    std::memcpy(nonce_plus_ciphertext, nonce, sizeof nonce);

    std::memcpy(
        nonce_plus_ciphertext + sizeof nonce, ciphertext, ciphertext_len);

    delete[] ciphertext;

    *outlen = ciphertext_len + sizeof nonce;

    return nonce_plus_ciphertext;
}

/**
* Asymmetric decryption of a ciphertext using a provided secret key
*
* @param self
* @param outlen The bytes length of decrypted text
* @param fullcard The QR code ID content
* @param fullcard_len bytes length of fullcard
* @param encrypted The encrypted data
* @param encrypted_len The bytes length of encrypted
* @return The decrypted text
*/

MODULE_API
unsigned char* idpass_lite_decrypt_with_card(void* self,
                                             int* outlen,
                                             unsigned char* fullcard,
                                             int fullcard_len,
                                             unsigned char* encrypted,
                                             int encrypted_len)
{
    if (self == nullptr || outlen == nullptr || fullcard == nullptr 
        || fullcard_len <= 0 || encrypted == nullptr || encrypted_len <= 0) {
        return nullptr; 
    }
    Context* context = (Context*)self;
    int len = encrypted_len - crypto_box_NONCEBYTES - crypto_box_MACBYTES;
    *outlen = 0;
    if (len <= 0) {
        return nullptr;
    }

    idpass::IDPassCards cards;
    idpass::IDPassCard card;

    if (!helper::decryptCard(fullcard,
                             fullcard_len,
                             context->m_keyset,
                             card,
                             cards)) {
        return nullptr;
    }

    if (!context->verify_chain(cards)) {
        return nullptr;
    }
    unsigned char card_skpk[crypto_sign_SECRETKEYBYTES];
    std::memcpy(
        card_skpk, card.encryptionkey().data(), card.encryptionkey().size());

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
            plaintext, ciphertext, ciphertext_len, nonce, pubkey, privkey)
        != 0) {
        delete[] ciphertext;
        context->ReleaseByteArray(plaintext);
        return nullptr;
    }

    delete[] ciphertext;
    *outlen = len;
    return plaintext;
}

/**
* Generates an AEAD symmetric encryption key.
*
* @param self
* @param key The generated encryption key
* @param key_len The length of generated encryption key
* @return Returns 0 on success
*/

MODULE_API
int idpass_lite_generate_encryption_key(unsigned char* key, int key_len)
{
    if (key_len != crypto_aead_chacha20poly1305_IETF_KEYBYTES || key == nullptr) {
        return 1;
    }

    crypto_aead_chacha20poly1305_keygen(key);
    return 0;
}

/**
* Generates an ED25519 key
*
* @param self
* @param key The generated ED25519 key
* @param key_len The length of generated key
* @return Returns 0 on success
*/

MODULE_API
int idpass_lite_generate_secret_signature_keypair(unsigned char* pk, 
    int pklen, unsigned char* sk, int sklen)
{
    if (sklen != crypto_sign_SECRETKEYBYTES || sk == nullptr 
        || pklen != crypto_sign_PUBLICKEYBYTES || pk == nullptr) {
        return 1;
    }

    return crypto_sign_keypair(pk, sk);
}

/**
* Symmetric decryption of the fullcard QR code ID.
*
* @param self
* @param ecard_buf The fullcard bytes
* @param ecard_buf_len Length bytes of ecard_buf
* @param key The AEAD symmetric decryption key
* @param key_len Length bytes of key
* @return Returns 0 on success and decrypted content stored in ecard_buf
*/

MODULE_API
int idpass_lite_card_decrypt(void* self,
                             unsigned char* ecard_buf,
                             int* ecard_buf_len,
                             unsigned char* key,
                             int key_len)
{
    Context* context = (Context*)self;

    if (key_len != crypto_aead_chacha20poly1305_IETF_KEYBYTES
        || key == nullptr || self == nullptr || 
        ecard_buf == nullptr || ecard_buf_len == nullptr || *ecard_buf_len <= 0) 
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

/**
* Verify the signature of msg using pubkey.
*
* @param self
* @param msg The message
* @param msg_len Length of message
* @param signature Signature of message
* @param signature_len The length of bytes of signature
* @pubkey Public key that generated the signature
* @pubkey_len Length of bytes of pubkey
* @return Returns 0 if pubkey verifies signature of msg
*/

MODULE_API
int idpass_lite_verify_with_card(void* self,
                                 unsigned char* msg,
                                 int msg_len,
                                 unsigned char* signature,
                                 int signature_len,
                                 unsigned char* pubkey,
                                 int pubkey_len)
{
    Context* context = (Context*)self;

    if (pubkey_len != crypto_sign_PUBLICKEYBYTES || pubkey == nullptr
        || signature_len != crypto_sign_BYTES || signature == nullptr
        || msg == nullptr || msg_len <= 0 || self == nullptr) {
        return 1;
    }

    int status = crypto_sign_verify_detached(signature, msg, msg_len, pubkey);
    return status;
}

/**
* Signs data with user's QR code ID.
*
* @param self
* @param outlen Bytes length of returned signature
* @param encrypted_card User's QR code ID
* @param encrypted_card_len Bytes length of encrypted_card
* @param data The input data to be signed
* @param data_len Bytes length of data
* @return Returns the signature
*/

MODULE_API int 
idpass_lite_sign_with_card(void* self,
                           unsigned char* sig,
                           int sig_len,
                           unsigned char* encrypted_card,
                           int encrypted_card_len,
                           unsigned char* data,
                           int data_len)
{
    if (sig == nullptr || sig_len != crypto_sign_BYTES || 
        encrypted_card == nullptr || encrypted_card_len <= 0 ||
        data == nullptr || data_len <= 0 || self == nullptr) 
    {
        return 1; 
    }

    Context* context = (Context*)self;

    idpass::IDPassCards cards;
    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->m_keyset,
                             card,
                             cards)) {
        return 2;
    }

    if (!context->verify_chain(cards)) {
        return 3;
    }

    // use ed25519 to sign
    if (crypto_sign_detached(sig,
                             nullptr,
                             data,
                             data_len,
                             (const unsigned char*)card.encryptionkey().data())
        != 0) {
        LOGI("crypto_sign: error");
        return 4;
    }

    return 0;
}

/**
* Returns the QR code bitmap of data.
*
* @param self
* @param data The input data
* @param data_len Bytes lngth of data
* @param *qrsize The square side dimension of QR code
* @return The bitmap representation of data
*/

// Returns the QR Code encoding in bits with square dimension len
MODULE_API unsigned char* idpass_lite_qrpixel(void* self,
                                              const unsigned char* data,
                                              int data_len,
                                              int* qrsize)
{
    if (self == nullptr || data == nullptr
        || data_len <= 0 | qrsize == nullptr) 
    {
        return nullptr; 
    }
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

/**
* Returns the QR code bitmap of data.
*
* @param self
* @param *outlen The bytes length of returned data
* @param data The input data
* @param data_len Bytes lngth of data
* @param *qrsize The square side dimension of QR code
* @return The bitmap representation of data
*/

MODULE_API unsigned char* idpass_lite_qrpixel2(void* self,
                                               int* outlen,
                                               const unsigned char* data,
                                               int data_len,
                                               int* qrsize)
{
    if (self == nullptr || outlen == nullptr 
        || data == nullptr || data_len <= 0
        || qrsize == nullptr) 
    {
        return nullptr; 
    }
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

/**
* A generic function to adjust settings of the calling context.
* It consist of a sub-command prefix by IOCTL_* followed by
* command-specific parameters.
*
* @param self Calling context
* @param outlen The count of bytes returned
* @param iobuf The input/output command buffer
* @param iobuf_len The bytes length of iobuf parameter
* @return void* Command-specific returned data buffer
*/

MODULE_API
void* idpass_lite_ioctl(void* self,
                        int* outlen,
                        unsigned char* iobuf,
                        int iobuf_len)

{
    if (!iobuf || iobuf_len <= 0 || self == nullptr) {
        return nullptr;
    }
    Context* context = (Context*)self;
    std::lock_guard<std::mutex> guard(context->ctxMutex);

    if (outlen) {
        *outlen = 0;
    }

    unsigned char cmd = iobuf[0];
    switch (cmd) {
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
        switch (iobuf[1]) {
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

/**
* Computes full facial dimension of a face.
*
* @param self
* @param photo The face photo
* @param photo_len Bytes length of photo
* @param facearray The float[128] array with 4 bytes per float
* @return Returns count of detected faces in photo
*/

MODULE_API int
idpass_lite_face128d(void* self, char* photo, int photo_len, float* faceArray)
{

    if (self == nullptr || photo == nullptr || photo_len <= 0
        || faceArray == nullptr) 
    {
        return 0;
    } 
    Context* context = (Context*)self;
    return dlib_api::computeface128d(photo, photo_len, faceArray);
}

/**
* Computes full facial dimension of a face.
*
* @param self
* @param photo The face photo
* @param photo_len Bytes length in photo
* @param buf The facial dimension float[128] as bytes
* @return Returns the count of faces detected in photo
*/

MODULE_API int idpass_lite_face128dbuf(void* self,
                                       char* photo,
                                       int photo_len,
                                       unsigned char* buf)
{
    if (self == nullptr || photo == nullptr || photo_len <= 0
        || buf == nullptr) 
    {
        return 0;
    } 
    Context* context = (Context*)self;
    float f4[128];
    int face_count = dlib_api::computeface128d(photo, photo_len, f4);

    if (face_count == 1) {
        bin16::f4_to_f4b(f4, 128, buf);
    }

    return face_count;
}

/**
* Computes half facial dimension of a face.
*
* @param self
* @param photo The face photo.
* @param photo_len Bytes length of photo
* @param facearray The float[64] with 2 bytes per float
* @return Returns the count of detected faces in photo
*/

MODULE_API
int idpass_lite_face64d(void* self,
                        char* photo,
                        int photo_len,
                        float* facearray)
{
    if (self == nullptr || photo == nullptr || photo_len <= 0
        || facearray == nullptr) 
    {
        return 0;
    } 
    Context* context = (Context*)self;
    float fdim[128];
    int facecount = dlib_api::computeface128d(photo, photo_len, fdim);
    bin16::f4_to_f2(fdim, 64, facearray);
    return facecount;
}

/**
* Computes half facial dimension of a face.
*
* @param self
* @param photo The face photo.
* @param photo_len Bytes length of photo
* @param facearray The float[64] with 2 bytes per float in byte array format
* @return Returns the count of detected faces in photo
*/

MODULE_API int idpass_lite_face64dbuf(void* self,
                                      char* photo,
                                      int photo_len,
                                      unsigned char* buf)
{
    if (self == nullptr || photo == nullptr || photo_len <= 0
        || buf == nullptr) 
    {
        return 0;
    } 
    Context* context = (Context*)self;
    float f4[128];
    int face_count = dlib_api::computeface128d(photo, photo_len, f4);

    if (face_count == 1) {
        bin16::f4_to_f2b(f4, 64, buf);
    }

    return face_count;
}

MODULE_API
int idpass_lite_compare_face_photo(void* self,
                                   char* face1,
                                   int face1_len,
                                   char* face2,
                                   int face2_len,
                                   float* fdiff)
{
    Context* context = (Context*)self;

    if (face1 == nullptr || face2 == nullptr || face1_len <= 0
        || face2_len <= 0 || self == nullptr || fdiff == nullptr) {
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

/**
* Substracts two faces face1 and face2 and stores result inot fdiff
*
* @param self
* @param face1 The first face input
* @param face1_len Length of face1
* @param face2 The second face input
* @param face2_len Length of face2
* @param fdiff Where to store the computation result
* @return Returns 0 on success subtraction
*/

MODULE_API
int idpass_lite_compare_face_template(unsigned char* face1,
                                      int face1_len,
                                      unsigned char* face2,
                                      int face2_len,
                                      float* fdiff)
{
    if (face1 == nullptr || face1_len <= 0 || face2 == nullptr || 
        face2_len <= 0 || fdiff == nullptr) 
    {
        return 1;
    }

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

/**
* Generate a self-signed certificate with the provided secretkey.
*
* @param self
* @param skpk The certificates private key
* @param skpk_len The bytes length of skpk
* @param outlen The bytes length of returned self-signed certificate
* @return Returns a self-sign certificate with the provided private key
*/

MODULE_API
unsigned char* idpass_lite_generate_root_certificate(unsigned char* skpk,
                                                     int skpk_len,
                                                     int* outlen)
{
    if (skpk_len != crypto_sign_SECRETKEYBYTES || skpk == nullptr
        || outlen == nullptr) {
        return nullptr;
    }

    unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_ed25519_sk_to_pk(pubkey, skpk);
    unsigned char signature[crypto_sign_BYTES]; // 64

    if (crypto_sign_detached(signature, nullptr, pubkey, sizeof pubkey, skpk)
        != 0) {
        return nullptr;
    }

    api::Certificate rootCERT;
    //rootCERT.set_privkey(skpk, skpk_len);
    rootCERT.set_pubkey(pubkey, crypto_sign_PUBLICKEYBYTES);
    rootCERT.set_signature(signature, crypto_sign_BYTES);
    rootCERT.set_issuerkey(pubkey, crypto_sign_PUBLICKEYBYTES);
    int n = rootCERT.ByteSizeLong();
    *outlen = n;
    unsigned char* buf = M::NewByteArray(n);
    rootCERT.SerializeToArray(buf, n);

    return buf;
}

/**
* Generate an intermediate certificate with the provided secretkey of signer
* and public key of the intermediate certificate.
*
* @param self
* @param parent_skpk The private key of the signer
* @param parent_skpk_len The length bytes of parent_skpk
* @param child_pubkey The public key of to-be-signed certificate
* @param child_pubkey_len The bytes length of child_pubkey
* @param outlen The bytes length of returned signed intermediate certificate
* @return Returns a signed intermediate certificate
*/

MODULE_API
unsigned char*
idpass_lite_generate_child_certificate(const unsigned char* parent_skpk,
                                       int parent_skpk_len,
                                       const unsigned char* child_pubkey,
                                       int child_pubkey_len,
                                       int* outlen)
{
    // TODO root vs intermed check???
    if (parent_skpk_len != crypto_sign_SECRETKEYBYTES || parent_skpk == nullptr
        || child_pubkey_len != crypto_sign_PUBLICKEYBYTES
        || child_pubkey == nullptr || outlen == nullptr) {
        return nullptr;
    }

    unsigned char issuerkey[crypto_sign_PUBLICKEYBYTES];
    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_ed25519_sk_to_pk(issuerkey, parent_skpk);

    // sign the child's public key
    if (crypto_sign_detached(signature,
                             nullptr,
                             child_pubkey,
                             crypto_sign_PUBLICKEYBYTES,
                             parent_skpk)
        != 0) {
        return nullptr;
    }

    api::Certificate intermedCert;
    intermedCert.set_pubkey(child_pubkey, crypto_sign_PUBLICKEYBYTES);
    intermedCert.set_signature(signature, crypto_sign_BYTES);
    intermedCert.set_issuerkey(issuerkey, crypto_sign_PUBLICKEYBYTES);

    int n = intermedCert.ByteSizeLong();
    unsigned char* buf = M::NewByteArray(n);
    intermedCert.SerializeToArray(buf, n);

    *outlen = n;
    return buf;
}


/**
* Addes the public key into revocation list.
*
* @param self
* @param pubkey The public key to be revocated
* @param pubkey_len Length bytes of pubkey
* @return Returns 0 on success
*/

MODULE_API
int idpass_lite_add_revoked_key(unsigned char* pubkey, int pubkey_len)
{
    if (pubkey == nullptr || pubkey_len != crypto_sign_PUBLICKEYBYTES) {
        return 1;
    }

    std::lock_guard<std::mutex> guard(g_mutex);

    std::array<unsigned char, 32> revoked_key;
    std::copy(pubkey, pubkey + pubkey_len, std::begin(revoked_key));
    g_revokedKeys.push_back(revoked_key);

    return 0;
}

/**
* Saves the QR code data into a bitmap file.
*
* @param self
* @param data The QR code content data
* @param data_len Bytes length of data
* @param bitmapfile The output filename
* @return Returns 0 on success file save
*/

// Saves the QR Code encoding to a bitmap file
MODULE_API int idpass_lite_saveToBitmap(void* self,
                                        unsigned char* data,
                                        int data_len,
                                        const char* bitmapfile)
{
    if (self == nullptr || data == nullptr || data_len <= 0
        || bitmapfile == nullptr) 
    {
        return 1; 
    }
    Context* context = (Context*)self;

    return qrcode_saveToBitmap(data, data_len, bitmapfile, context->qrcode_ecc);
}

/**
* Experimential test of length-prefixed returned blob
*
* @param self Calling context
* @param typ Generic type parameter
* @return Returns a 4 bytes length-prefix byte array
*/

MODULE_API
unsigned char* idpass_lite_uio(void* self, int typ) 
{
    Context* context = (Context*)self;
    if (self == nullptr) {
        return nullptr; 
    }

    api::Ident ident;
    ident.set_surname("Doe");
    ident.set_givenname("John");
    std::vector<unsigned char> _ident(ident.ByteSizeLong());
    ident.SerializeToArray(_ident.data(), _ident.size());
    int len = _ident.size();
    unsigned char* c_buf = context->NewByteArray(sizeof len + len);

    std::memcpy(c_buf, &len, sizeof len);
    std::memcpy(c_buf + sizeof len, _ident.data(), _ident.size());

    return c_buf;
}

MODULE_API
int idpass_lite_compute_hash(unsigned char* data,
                             int data_len,
                             unsigned char* hash,
                             int hash_len)
{
    if (data == nullptr || data_len <= 0 || hash == nullptr
        || hash_len != crypto_generichash_BYTES) {
        return 1;
    }

    return crypto_generichash(hash, hash_len, data, data_len, NULL, 0);
}

#ifdef __cplusplus
}
#endif
