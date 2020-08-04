#include "idpass.h"

#include "CCertificate.h"
#include "Cert.h"
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

    std::array<unsigned char, crypto_aead_chacha20poly1305_IETF_KEYBYTES>
        encryptionKey; // 32
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> signatureKey; // 64
    std::list<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>>
        verificationKeys; // 32n

    api::KeySet m_cryptoKeys;

    std::vector<CCertificate> m_rootCerts;
    std::vector<CCertificate> m_intermedCerts;

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

    bool verify_chain(idpass::IDPassCards& fullCard)
    {
        if (fullCard.certificates_size() > 0) {
            std::vector<CCertificate> chain;

            try {
                for (auto& c : fullCard.certificates()) {
                    CCertificate cer(c);
                    // context->m_intermedCerts.push_back(cer);
                    chain.push_back(cer);
                }
            } catch (std::exception& e) {
                return 3;
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
                                    return std::memcmp(m.value.pubkey().data(),
                                                       c->value.pubkey().data(),
                                                       32)
                                           == 0;
                                })
                   != m_rootCerts.end();
        };

        if (chain.size() == 0) {
            return false;
        }

        CCertificate* pCert = &chain.back();
        const char* startkey = pCert->value.pubkey().data();

        while (pCert != nullptr) {
            if (pCert->hasValidSignature()) {
                if (helper::isRevoked(
                        REVOKED_KEYS, pCert->value.pubkey().data(), 32)) {
                    return false;
                }
                if (!pCert->isSelfSigned()) {
                    pCert = pCert->getIssuer(chain, m_rootCerts);
                    if (pCert == nullptr
                        || std::memcmp(
                               pCert->value.pubkey().data(), startkey, 32)
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

        return true;
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
    std::lock_guard<std::mutex> guard(m_mtx);
    m_m.emplace_back(n);
    return m_m.back().data();
}

bool ReleaseByteArray(void* addr)
{
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

MODULE_API
int idpass_lite_verify_certificate(void* self,
                                   unsigned char* fullcard,
                                   int fullcard_len)
{
    Context* context = (Context*)self;

    if (fullcard == nullptr || fullcard_len == 0) {
        return -1;
    }

    idpass::IDPassCards cards;
    if (!cards.ParseFromArray(fullcard, fullcard_len)) {
        return -1;
    }

    int count = cards.certificates_size();
    if (count > 0) {
        if (!context->verify_chain(cards)) {
            return -1;
        }
    }

    return count;
}

MODULE_API
int idpass_lite_add_certificates(void* self,
                                 unsigned char* certs_buf,
                                 int certs_buf_len)
{
    Context* context = (Context*)self;

    if (certs_buf == nullptr || certs_buf_len == 0) {
        return 1;
    }

    api::Certificats intermedCerts;
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

MODULE_API
void* idpass_lite_init(unsigned char* cryptokeys_buf,
                       int cryptokeys_buf_len,
                       unsigned char* rootcerts_buf,
                       int rootcerts_buf_len)
{
    if (!cryptokeys_buf || !rootcerts_buf || cryptokeys_buf_len == 0
        || rootcerts_buf_len == 0) {
        LOGI("invalid params");
        return nullptr;
    }

    api::KeySet cryptoKeys;
    api::Certificats rootCerts;

    if (!cryptoKeys.ParseFromArray(cryptokeys_buf, cryptokeys_buf_len)
        || !rootCerts.ParseFromArray(rootcerts_buf, rootcerts_buf_len)) {
        LOGI("invalid params deserialization");
        return nullptr;
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
            if (!cer.hasPrivateKey()) {
                return nullptr;
            }
            context->m_rootCerts.push_back(cer);
        }
    } catch (std::exception& e) {
        return nullptr;
    }

    context->m_cryptoKeys = cryptoKeys;

    context->facediff_half = DEFAULT_FACEDIFF_HALF;
    context->facediff_full = DEFAULT_FACEDIFF_FULL;
    context->fdimension = false; // defaults to 64/2
    context->qrcode_ecc = ECC_MEDIUM;
    std::memset(
        context->acl, 0x00, sizeof context->acl); // default all fields priv

    return static_cast<void*>(context);
}

MODULE_API
void idpass_lite_freemem(void* self, void* buf)
{
    Context* context = (Context*)self;
    if (!context->ReleaseByteArray(buf)) {
        if (context == buf) {
            M::releaseContext(context);
        }
    }
}

MODULE_API
unsigned char* idpass_lite_create_card_with_face(void* self,
                                                 int* outlen,
                                                 unsigned char* ident_buf,
                                                 int ident_buf_len)
{
    if (self == nullptr || outlen == nullptr || ident_buf == nullptr
        || ident_buf_len == 0) {
        return nullptr;
    }

    Context* context = (Context*)self;
    *outlen = 0;
    unsigned long int epochSeconds = std::time(nullptr);
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
        std::memcpy(card_signerPublicKey, cc.value.pubkey().data(), 32);
    } else {
        crypto_sign_ed25519_sk_to_pk(
            card_signerPublicKey,
            reinterpret_cast<const unsigned char*>(
                context->m_cryptoKeys.sigkey().data()));
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

    privateRegionEncrypted_len
        = helper::encrypt_object(privateRegion,
                                 context->m_cryptoKeys.enckey().data(),
                                 privateRegionEncrypted);

    ////////////////////////////////////////////////////////////
    // concatinate privateRegion and publicRegion (in this order)
    // into a blob and then signed this blob
    std::vector<unsigned char> blob_privateRegion;
    std::vector<unsigned char> blob_publicRegion;
    std::vector<unsigned char> priv_pub_blob;
    unsigned char priv_pub_blob_signature[crypto_sign_BYTES];

    helper::serialize(privateRegion, blob_privateRegion);
    helper::serialize(publicRegion, blob_publicRegion);
    std::copy(blob_privateRegion.data(),
              blob_privateRegion.data() + blob_privateRegion.size(),
              std::back_inserter(priv_pub_blob));
    std::copy(blob_publicRegion.data(),
              blob_publicRegion.data() + blob_publicRegion.size(),
              std::back_inserter(priv_pub_blob));
    // context->m_cryptoKeys.sigkey().data() ---> const char*
    helper::sign_object(priv_pub_blob,
                        context->m_cryptoKeys.sigkey().data(),
                        priv_pub_blob_signature);

    ///////////////////////////////
    // assemble final output object
    idpass::IDPassCards idpassCards;
    idpassCards.set_signature(priv_pub_blob_signature, crypto_sign_BYTES);
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
            c->set_pubkey(cer.value.pubkey().data());
            c->set_signature(cer.value.signature().data());
            c->set_issuerkey(cer.value.issuerkey().data());
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

// Returns CardDetails object if face matches
MODULE_API unsigned char*
idpass_lite_verify_card_with_face(void* self,
                                  int* outlen,
                                  unsigned char* encrypted_card,
                                  int encrypted_card_len,
                                  char* photo,
                                  int photo_len)
{
    Context* context = (Context*)self;
    *outlen = 0;

    idpass::IDPassCards cards;
    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->m_cryptoKeys,
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

// returns CardDetails object if pin matches
MODULE_API unsigned char*
idpass_lite_verify_card_with_pin(void* self,
                                 int* outlen,
                                 unsigned char* encrypted_card,
                                 int encrypted_card_len,
                                 const char* pin)
{
    Context* context = (Context*)self;
    *outlen = 0;

    idpass::IDPassCards cards;
    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->m_cryptoKeys,
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

MODULE_API unsigned char*
idpass_lite_encrypt_with_card(void* self,
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

    idpass::IDPassCards cards;
    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->m_cryptoKeys,
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

MODULE_API
unsigned char* idpass_lite_decrypt_with_card(void* self,
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

MODULE_API
int idpass_lite_generate_encryption_key(unsigned char* key, int key_len)
{
    if (key_len != crypto_aead_chacha20poly1305_IETF_KEYBYTES) {
        return 1;
    }

    crypto_aead_chacha20poly1305_keygen(key);
    return 0;
}

MODULE_API
int idpass_lite_generate_secret_signature_key(unsigned char* sig_skpk,
                                              int sig_skpk_len)
{
    if (sig_skpk_len != crypto_sign_SECRETKEYBYTES) {
        return 1;
    }

    unsigned char sig_pk[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_keypair(sig_pk, sig_skpk);
    return 0;
}

MODULE_API
int idpass_lite_card_decrypt(void* self,
                             unsigned char* ecard_buf,
                             int* ecard_buf_len,
                             unsigned char* key,
                             int key_len)
{
    Context* context = (Context*)self;

    if (key_len != crypto_aead_chacha20poly1305_IETF_KEYBYTES
        || key == nullptr) {
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
        || msg == nullptr || msg_len <= 0) {
        return 1;
    }

    int status = crypto_sign_verify_detached(signature, msg, msg_len, pubkey);
    return status;
}

MODULE_API unsigned char*
idpass_lite_sign_with_card(void* self,
                           int* outlen,
                           unsigned char* encrypted_card,
                           int encrypted_card_len,
                           unsigned char* data,
                           int data_len)
{
    Context* context = (Context*)self;
    *outlen = 0;

    unsigned char* signature = nullptr;

    idpass::IDPassCards cards;
    idpass::IDPassCard card;

    if (!helper::decryptCard(encrypted_card,
                             encrypted_card_len,
                             context->m_cryptoKeys,
                             card,
                             cards)) {
        return nullptr;
    }

    if (!context->verify_chain(cards)) {
        return nullptr;
    }

    signature = context->NewByteArray(crypto_sign_BYTES);
    unsigned long long smlen;

    // use ed25519 to sign
    if (crypto_sign_detached(signature,
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
MODULE_API unsigned char* idpass_lite_qrpixel(void* self,
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

MODULE_API unsigned char* idpass_lite_qrpixel2(void* self,
                                               int* outlen,
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

MODULE_API
void* idpass_lite_ioctl(void* self,
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

MODULE_API int
idpass_lite_face128d(void* self, char* photo, int photo_len, float* faceArray)
{
    Context* context = (Context*)self;
    return dlib_api::computeface128d(photo, photo_len, faceArray);
}

MODULE_API int idpass_lite_face128dbuf(void* self,
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
int idpass_lite_face64d(void* self,
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

MODULE_API int idpass_lite_face64dbuf(void* self,
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
int idpass_lite_compare_face_photo(void* self,
                                   char* face1,
                                   int face1_len,
                                   char* face2,
                                   int face2_len,
                                   float* fdiff)
{
    Context* context = (Context*)self;

    if (face1 == nullptr || face2 == nullptr || face1_len == 0
        || face2_len == 0) {
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
int idpass_lite_compare_face_template(unsigned char* face1,
                                      int face1_len,
                                      unsigned char* face2,
                                      int face2_len,
                                      float* fdiff)
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

    api::Certificat rootCERT;
    rootCERT.set_privkey(skpk, skpk_len);
    rootCERT.set_pubkey(pubkey, crypto_sign_PUBLICKEYBYTES);
    rootCERT.set_signature(signature, crypto_sign_BYTES);
    rootCERT.set_issuerkey(pubkey, crypto_sign_PUBLICKEYBYTES);
    int n = rootCERT.ByteSizeLong();
    *outlen = n;
    unsigned char* buf = M::NewByteArray(n);
    rootCERT.SerializeToArray(buf, n);

    return buf;
}

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

    api::Certificat intermedCert;
    intermedCert.set_pubkey(child_pubkey, crypto_sign_PUBLICKEYBYTES);
    intermedCert.set_signature(signature, crypto_sign_BYTES);
    intermedCert.set_issuerkey(issuerkey, crypto_sign_PUBLICKEYBYTES);

    int n = intermedCert.ByteSizeLong();
    unsigned char* buf = M::NewByteArray(n);
    intermedCert.SerializeToArray(buf, n);

    *outlen = n;
    return buf;
}

MODULE_API
int idpass_lite_add_revoked_key(unsigned char* pubkey, int pubkey_len)
{
    if (pubkey == nullptr || pubkey_len != crypto_sign_PUBLICKEYBYTES) {
        return 1;
    }

    std::lock_guard<std::mutex> guard(g_mutex);
    struct stat st;
    std::ofstream outfile(REVOKED_KEYS,
                          std::ios::out | std::ios::binary | std::ios::app);
    outfile.write(reinterpret_cast<const char*>(pubkey), pubkey_len);
    outfile.close();

    return 0;
}

// Saves the QR Code encoding to a bitmap file
MODULE_API int idpass_lite_saveToBitmap(void* self,
                                        unsigned char* data,
                                        int data_len,
                                        const char* bitmapfile)
{
    Context* context = (Context*)self;

    return qrcode_saveToBitmap(data, data_len, bitmapfile, context->qrcode_ecc);
}

#ifdef __cplusplus
}
#endif
