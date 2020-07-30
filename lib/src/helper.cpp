#include "sodium.h"
#include "bin16.h"

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus

#include "dlibapi.h"
#include "proto/card_access/card_access.pb.h"

#include <cmath>
#include <fstream>
#include <ios>
#include <map>
#include <sstream>
#include <vector>
#include <list>

#include "helper.h"

#ifdef ANDROID
  #include <android/log.h>

  #define LOGI(...) \
      ((void)__android_log_print(ANDROID_LOG_INFO, "idpassapi::helper", __VA_ARGS__))
#else
  #define LOGI(...)
#endif

namespace helper
{
// trim from start (in place)
static inline void ltrim(std::string& s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string& s)
{
    s.erase(std::find_if( s.rbegin(), s.rend(), [](int ch) { 
        return !std::isspace(ch); 
    }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string& s)
{
    ltrim(s);
    rtrim(s);
}

std::vector<std::string> split(std::string& s, char delimiter)
{
    trim(s);

    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        trim(token);
        tokens.push_back(token);
    }

    return tokens;
}

std::map<std::string, std::string> parseToMap(std::string& s)
{
    trim(s);
    std::map<std::string, std::string> m;

    std::string key, val;
    std::istringstream iss(s);

    for (std::string& elem : split(s, ',')) {
        std::vector<std::string> p = split(elem, ':');
        if (p.size() == 2) {
            std::string k = p[0];
            std::string v = p[1];
            m[k] = v;
        }
    }

    return m;
}

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

double computeFaceDiff(char* photo, int photo_len, const std::string& cardAccessFaceBuf)
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

bool decryptCard(
    unsigned char* full_card_buf,
    int full_card_buf_len,
    const unsigned char* encryptionKey,
    const unsigned char* signatureKey,
    const std::list<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>>&
        verificationKeys,
    idpass::IDPassCard& card)
{
    idpass::IDPassCards fullCard;
    if (!fullCard.ParseFromArray(full_card_buf, full_card_buf_len)) {
        return false;
    }

    ////////////////////
    const unsigned char* ecardbuf = reinterpret_cast<const unsigned char*>(fullCard.encryptedcard().data());
    int ecardbuf_len = fullCard.encryptedcard().size();

    const unsigned char* signature = reinterpret_cast<const unsigned char*>(fullCard.signature().data()); 
    const unsigned char* pubkey = reinterpret_cast<const unsigned char*>(fullCard.signerpublickey().data());

    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> signerPublicKey;
    std::copy(pubkey, pubkey + crypto_sign_PUBLICKEYBYTES, std::begin(signerPublicKey));
    // Check signerPublicKey is in our trusted list
    if (std::find(verificationKeys.begin(),
                  verificationKeys.end(),
                  signerPublicKey)
        == verificationKeys.end()) {
        LOGI("signerPublicKey not found");
        return false;
    }

    idpass::PublicSignedIDPassCard publicRegion;
    if (fullCard.has_publiccard()) {
        publicRegion = fullCard.publiccard();
    }
    ////////////////////
    int privateRegionBuf_len = ecardbuf_len - crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
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
            encryptionKey)
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

        std::copy(blob_publicRegion.data(),
                  blob_publicRegion.data() + blob_publicRegion.size(),
                  std::back_inserter(priv_pub_blob));
        /////////////////////////////////////

        if (crypto_sign_verify_detached(
            signature, 
            priv_pub_blob.data(),
            priv_pub_blob.size(),
            pubkey)
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

bool isRevoked(const char* filename, unsigned char* key, int key_len)
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

        if (std::find(revokedkeys.begin(),
                      revokedkeys.end(),
                      rkey)
            != revokedkeys.end()) {
            return true;
        }
    }

    return false;
}

bool sign_object(idpass::IDPassCard& object, unsigned char* key, unsigned char* sig)
{
    int buf_len = object.ByteSizeLong();
    unsigned char* buf = new unsigned char[buf_len];

    if (!object.SerializeToArray(buf, buf_len)) {
        LOGI("serialize error1");
        delete[] buf;
        return false;
    }

    if (crypto_sign_detached(sig,
                             nullptr,
                             buf,
                             buf_len,
                             key)
        != 0) {
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

    if (crypto_sign_detached(sig,
                             nullptr,
                             buf,
                             buf_len,
                             key)
        != 0) {
        LOGI("crypto_sign error");
        delete[] buf;
        return false;
    }

    return true;
}

bool sign_object(idpass::CardDetails& object,
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

    if (crypto_sign_detached(sig,
                             nullptr,
                             buf,
                             buf_len,
                             key)
        != 0) {
        LOGI("crypto_sign error");
        delete[] buf;
        return false;
    }

    return true;
}

bool sign_object(std::vector<unsigned char>& blob,
                 unsigned char* key,
                 unsigned char* sig)
{
    if (crypto_sign_detached(sig,
                             nullptr,
                             blob.data(),
                             blob.size(),
                             key)
        != 0) {
        LOGI("crypto_sign error");
        return false;
    }

    return true;
}

int encrypt_object(idpass::SignedIDPassCard& object,
                    unsigned char* key,
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

    if (crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext.data(),
                                                  &ciphertext_len,
                                                  buf.data(),
                                                  buf_len,
                                                  NULL,
                                                  0,
                                                  NULL,
                                                  nonce,
                                                  key)
        != 0) {
        LOGI("ietf_encrypt failed");
        return 0;
    }

    const int nonce_encrypted_len = sizeof nonce + ciphertext_len;
    std::copy(nonce, nonce + sizeof nonce, std::back_inserter(encrypted));
    std::copy(ciphertext.data(), ciphertext.data() + ciphertext_len, std::back_inserter(encrypted));

    return nonce_encrypted_len;
}

bool serialize(idpass::PublicSignedIDPassCard& object, std::vector<unsigned char>& buf)
{
    int len = object.ByteSizeLong();
    buf.resize(len);

    if (!object.SerializeToArray(buf.data(), len)) {
        LOGI("serialize error2");
        return false;
    }

    return true;
}

bool serialize(idpass::SignedIDPassCard& object, std::vector<unsigned char>& buf)
{
    int len = object.ByteSizeLong();
    buf.resize(len);

    if (!object.SerializeToArray(buf.data(), len)) {
        LOGI("serialize error2");
        return false;
    }

    return true;
}

} // helper

extern "C" void helper_hexdump(const void* data, int size, char* title)
{
    char ascii[17];
    size_t i, j;
    printf("\n[%s]\n",title);
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

#endif // __cplusplus
