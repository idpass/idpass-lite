#include "bin16.h"
#include "sodium.h"

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus

#include "dlibapi.h"
#include "helper.h"
#include "proto/api/api.pb.h"
#include "proto/idpasslite/idpasslite.pb.h"

#include <cmath>
#include <fstream>
#include <ios>
#include <list>
#include <map>
#include <sstream>
#include <vector>

#ifdef ANDROID
#include <android/log.h>

#define LOGI(...)               \
    ((void)__android_log_print( \
        ANDROID_LOG_INFO, "idpassapi::helper", __VA_ARGS__))
#else
#define LOGI(...)
#endif

namespace helper
{
float euclidean_diff(float face1[], float face2[], int n)
{
    double ret = 0.0;
    for (int i = 0; i < n; i++) {
        double dist
            = static_cast<double>(face1[i]) - static_cast<double>(face2[i]);
        ret += dist * dist;
    }
    return ret >= 0.0 ? (float)sqrt(ret) : (float)10.0;
}

double computeFaceDiff(char* photo,
                       int photo_len,
                       const std::string& cardAccessFaceBuf)
{
    double face_diff = 10.0;
    float F4[128];
    float input_f4[128];
    unsigned char* buf = (unsigned char*)cardAccessFaceBuf.data();
    int buf_len = cardAccessFaceBuf.size(); // either 128*4 or 64*2

    int face_count = dlib_api::computeface128d(photo, photo_len, &F4[0]);

    if (face_count == 1) { // only process if found 1 face

        if (buf_len == 128 * 4) {
            bin16::f4b_to_f4(buf, 128 * 4, input_f4);
            // calculate vector distance
            face_diff = euclidean_diff(input_f4, F4, 128);
        } else {
            float photoFace[128];
            bin16::f4_to_f2(F4, 128, photoFace);
            float cardAccessFace[64];
            bin16::f2b_to_f2(buf, buf_len, cardAccessFace);

            // calculate vector distance
            face_diff = euclidean_diff(cardAccessFace, photoFace, 64);
        }

    } else if (face_count == 0) {
        LOGI("no face found");
    } else {
        LOGI("many faces found");
    }

    return face_diff;
}

bool decryptCard(unsigned char* full_card_buf,
                 int full_card_buf_len,
                 api::KeySet& cryptoKeys,
                 idpass::IDPassCard& card,
                 idpass::IDPassCards& fullCard)
{
    if (!fullCard.ParseFromArray(full_card_buf, full_card_buf_len)) {
        return false;
    }

    ////////////////////
    const unsigned char* ecardbuf = reinterpret_cast<const unsigned char*>(
        fullCard.encryptedcard().data());
    int ecardbuf_len = fullCard.encryptedcard().size();

    const unsigned char* signature
        = reinterpret_cast<const unsigned char*>(fullCard.signature().data());
    const unsigned char* pubkey = reinterpret_cast<const unsigned char*>(
        fullCard.signerpublickey().data());

    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> signerPublicKey;
    std::copy(pubkey,
              pubkey + crypto_sign_PUBLICKEYBYTES,
              std::begin(signerPublicKey));

    bool found = false;
    for (auto& pub : cryptoKeys.verificationkeys()) {
        if (pub.typ() == api::byteArray_Typ_ED25519PUBKEY) {
            if (std::memcmp(pub.val().data(), pubkey, 32) == 0) {
                found = true;
                break;
            }
        }
    }

    if (!found) {
        return false;
    }

    idpass::PublicSignedIDPassCard publicRegion;
    if (fullCard.has_publiccard()) {
        publicRegion = fullCard.publiccard();
    }
    ////////////////////
    int privateRegionBuf_len
        = ecardbuf_len - crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
    unsigned char* privateRegionBuf = new unsigned char[privateRegionBuf_len];
    unsigned long long decrypted_len;

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    std::memcpy(nonce, ecardbuf, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            privateRegionBuf,
            &decrypted_len,
            NULL, // always
            ecardbuf + crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
            ecardbuf_len - crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
            NULL,
            0,
            nonce,
            reinterpret_cast<const unsigned char*>(cryptoKeys.encryptionkey().data()))
        != 0) {
        LOGI("decrypt error");
        delete[] privateRegionBuf;
        return false;
    }

    idpass::SignedIDPassCard privateRegion;
    bool flag = privateRegion.ParseFromArray(privateRegionBuf, decrypted_len);

    if (flag) {
        /////////////////////////////////////
        std::vector<unsigned char> blob_publicRegion;
        std::vector<unsigned char> priv_pub_blob;
        unsigned char priv_pub_blob_signature[crypto_sign_BYTES];

        helper::serialize(publicRegion, blob_publicRegion);

        std::copy(privateRegionBuf,
                  privateRegionBuf + /*privateRegionBuf_len*/ decrypted_len,
                  std::back_inserter(priv_pub_blob));

        if (publicRegion.ByteSizeLong() > 0) {
            std::copy(blob_publicRegion.data(),
                      blob_publicRegion.data() + blob_publicRegion.size(),
                      std::back_inserter(priv_pub_blob));
        }
        /////////////////////////////////////

        if (crypto_sign_verify_detached(
                signature, priv_pub_blob.data(), priv_pub_blob.size(), pubkey)
            != 0) {
            LOGI("crypto_sign error");
            flag = false;
        } else {
            card = privateRegion.card();
        }
    }

    delete[] privateRegionBuf;
    return flag;
}

bool isRevoked(const char* filename, const char* key, int key_len)
{
    struct stat st;
    if (stat(filename, &st) == 0) {
        if (st.st_size % 32 != 0) {
            throw std::runtime_error("revoked.keys malformed");
            return false;
        }
        std::list<std::array<char, crypto_sign_PUBLICKEYBYTES>> revokedkeys;
        std::array<char, crypto_sign_PUBLICKEYBYTES> rkey;
        FILE* file = NULL;
        size_t nread = 0;
        file = fopen(filename, "rb");
        if (file != NULL) {
            while ((nread = fread(rkey.data(), 1, rkey.size(), file)) > 0) {
                revokedkeys.push_back(rkey);
            }
            fclose(file);
        } else {
            throw std::runtime_error("revoked.keys open error");
        }

        std::copy(key, key + 32, std::begin(rkey));

        if (std::find(revokedkeys.begin(), revokedkeys.end(), rkey)
            != revokedkeys.end()) {
            return true;
        }
    }

    return false;
}

bool sign_object(idpass::IDPassCard& object,
                 unsigned char* key,
                 unsigned char* sig)
{
    int buf_len = object.ByteSizeLong();
    unsigned char* buf = new unsigned char[buf_len];

    if (!object.SerializeToArray(buf, buf_len)) {
        LOGI("serialize error1");
        delete[] buf;
        return false;
    }

    if (crypto_sign_detached(sig, nullptr, buf, buf_len, key) != 0) {
        LOGI("crypto_sign error");
        delete[] buf;
        return false;
    }

    return true;
}

bool sign_object(idpass::PublicSignedIDPassCard& object,
                 unsigned char* key,
                 unsigned char* sig)
{
    int buf_len = object.ByteSizeLong();
    unsigned char* buf = new unsigned char[buf_len];

    if (!object.SerializeToArray(buf, buf_len)) {
        LOGI("serialize error1");
        delete[] buf;
        return false;
    }

    if (crypto_sign_detached(sig, nullptr, buf, buf_len, key) != 0) {
        LOGI("crypto_sign error");
        delete[] buf;
        return false;
    }

    return true;
}

bool sign_object(idpass::CardDetails& object,
                 const unsigned char* key,
                 unsigned char* sig)
{
    int buf_len = object.ByteSizeLong();
    unsigned char* buf = new unsigned char[buf_len];

    if (!object.SerializeToArray(buf, buf_len)) {
        LOGI("serialize error1");
        delete[] buf;
        return false;
    }

    if (crypto_sign_detached(sig, nullptr, buf, buf_len, key) != 0) {
        LOGI("crypto_sign error");
        delete[] buf;
        return false;
    }

    return true;
}

bool sign_object(std::vector<unsigned char>& blob,
                 const char* key,
                 unsigned char* sig)
{
    if (crypto_sign_detached(sig,
                             nullptr,
                             blob.data(),
                             blob.size(),
                             reinterpret_cast<const unsigned char*>(key))
        != 0) {
        LOGI("crypto_sign error");
        return false;
    }

    return true;
}

int encrypt_object(idpass::SignedIDPassCard& object,
                   const char* key,
                   std::vector<unsigned char>& encrypted)
{
    int buf_len = object.ByteSizeLong();
    std::vector<unsigned char> buf(buf_len);

    if (!object.SerializeToArray(buf.data(), buf_len)) {
        LOGI("serialize error2");
        return 0;
    }

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES]; // 12
    randombytes_buf(nonce, sizeof nonce);

    int lenn = buf_len + crypto_aead_chacha20poly1305_IETF_ABYTES; // +16
    std::vector<unsigned char> ciphertext(lenn);
    unsigned long long ciphertext_len = 0;

    /*
    At most mlen + crypto_aead_chacha20poly1305_IETF_ABYTES bytes are put into
    c, and the actual number of bytes is stored into clen unless clen is a NULL
    pointer.
    */

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(),
            &ciphertext_len,
            buf.data(),
            buf_len,
            NULL,
            0,
            NULL,
            nonce,
            reinterpret_cast<const unsigned char*>(key))
        != 0) {
        LOGI("ietf_encrypt failed");
        return 0;
    }

    const int nonce_encrypted_len = sizeof nonce + ciphertext_len;
    std::copy(nonce, nonce + sizeof nonce, std::back_inserter(encrypted));
    std::copy(ciphertext.data(),
              ciphertext.data() + ciphertext_len,
              std::back_inserter(encrypted));

    return nonce_encrypted_len;
}

bool serialize(idpass::PublicSignedIDPassCard& object,
               std::vector<unsigned char>& buf)
{
    int len = object.ByteSizeLong();
    buf.resize(len);

    if (!object.SerializeToArray(buf.data(), len)) {
        LOGI("serialize error2");
        return false;
    }

    return true;
}

bool serialize(idpass::SignedIDPassCard& object,
               std::vector<unsigned char>& buf)
{
    int len = object.ByteSizeLong();
    buf.resize(len);

    if (!object.SerializeToArray(buf.data(), len)) {
        LOGI("serialize error2");
        return false;
    }

    return true;
}

bool is_valid_ed25519_key(const unsigned char* key)
{
    const char* msg = "attack at dawn!";
    unsigned char signature[crypto_sign_BYTES];
    unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];

    if (0 != crypto_sign_ed25519_sk_to_pk(pubkey, key)) {
        return false;
    }

    if (0
        != crypto_sign_detached(signature,
                                nullptr,
                                reinterpret_cast<const unsigned char*>(msg),
                                std::strlen(msg),
                                key)) {
        return false;
    }

    if (0
        != crypto_sign_verify_detached(
            signature,
            reinterpret_cast<const unsigned char*>(msg),
            std::strlen(msg),
            pubkey)) {
        return false;
    }

    return true;
}

bool is_valid(api::Certificates& rootcerts)
{
    for (auto& c : rootcerts.cert()) {
        if (c.privkey().size() == 64) { // root CA
            if (!is_valid_ed25519_key(reinterpret_cast<const unsigned char*>(
                    c.privkey().data()))) {
                return false;
            }
        } else { // intermed CA
        }
    }

    return true;
}

bool is_valid(api::KeySet& ckeys)
{
    if (ckeys.encryptionkey().size() != crypto_aead_chacha20poly1305_IETF_KEYBYTES
        || ckeys.signaturekey().size() != crypto_sign_SECRETKEYBYTES) {
        return false;
    }

    if (!is_valid_ed25519_key(
            reinterpret_cast<const unsigned char*>(ckeys.signaturekey().data()))) {
        return false;
    }

    if (ckeys.verificationkeys_size() > 0) {
        for (auto& verkey : ckeys.verificationkeys()) {
            if (verkey.typ() != api::byteArray_Typ_ED25519PUBKEY
                || verkey.val().size() != crypto_sign_PUBLICKEYBYTES) {
                return false;
            }
        }
    } else {
        unsigned char pubkey[32];
        crypto_sign_ed25519_sk_to_pk(pubkey, 
            reinterpret_cast<const unsigned char*>(ckeys.signaturekey().data()));
    }

    return true;
}

} // helper

extern "C" void helper_hexdump(const void* data, int size, char* title)
{
    char ascii[17];
    size_t i, j;
    printf("\n[%s]\n", title);
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' '
            && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

#endif // __cplusplus
