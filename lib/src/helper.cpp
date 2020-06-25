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

double computeFaceDiff(char* photo, int photo_len, const std::string& cardAccessFaceBuf)
{
    double face_diff = 10.0;
    float F4[128];
    float input_f4[128];
    unsigned char* buf = (unsigned char*)cardAccessFaceBuf.c_str();
    int buf_len = cardAccessFaceBuf.size(); // either 128*4 or 64*2

    int face_count = dlib_api::computeface128d(photo, photo_len, &F4[0]);

    if (face_count == 1) { // only process if found 1 face

        auto euclidean_diff = [](float face1[], float face2[], int n) {
            double ret = 0.0;
            for (int i = 0; i < n; i++) {
                double dist
                    = static_cast<double>(face1[i]) - static_cast<double>(face2[i]);
                ret += dist * dist;
            }
            return ret >= 0.0 ? (float)sqrt(ret) : (float)10.0;
        };

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

bool decryptCard(unsigned char* encrypted_card,
                 int encrypted_card_len,
                 const unsigned char* encryptionKey,
                 const unsigned char* signatureKey,
                 const std::list<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>> &verificationKeys,
                 idpass::SignedIDPassCard& ecard)
{
    unsigned char* cardserialized
        = new unsigned char[encrypted_card_len
                            - crypto_aead_chacha20poly1305_IETF_NPUBBYTES];

    unsigned long long decrypted_len;

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];

    std::memcpy(
        nonce, 
        encrypted_card, 
        crypto_aead_chacha20poly1305_IETF_NPUBBYTES);

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            cardserialized,
            &decrypted_len,
            NULL, // always
            encrypted_card + crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
            encrypted_card_len - crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
            NULL,
            0,
            nonce,
            encryptionKey)
    != 0) {
        LOGI("decrypt error");
        delete[] cardserialized;
        return false;
    }

    const bool flag = ecard.ParseFromArray(cardserialized, decrypted_len);
    delete[] cardserialized;

    if (flag) {
        // extract signerPublicKey and card member fields
        std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> signerPublicKey;
        std::copy(
            ecard.signerpublickey().c_str(),
            ecard.signerpublickey().c_str() + crypto_sign_PUBLICKEYBYTES,
            std::begin(signerPublicKey));

        // Check signerPublicKey is in our trusted list
        if (std::find(
            verificationKeys.begin(),
            verificationKeys.end(),
            signerPublicKey)
         == verificationKeys.end()) {
            LOGI("signerPublicKey not found");
            return false; 
        }

        int buf_len = ecard.card().ByteSizeLong();
        unsigned char* buf = new unsigned char[buf_len];

        // Seriliaze the card for signature verification
        if (!ecard.card().SerializeToArray(buf, buf_len)) {
            LOGI("serialize error1");
            delete[] buf;
            return false;
        }

        // verify the signature of idpass::IDPassCard against signerpublic key.
        if (crypto_sign_verify_detached(
            reinterpret_cast<const unsigned char*>(ecard.signature().c_str()), 
            buf,
            buf_len,
            reinterpret_cast<const unsigned char*>(ecard.signerpublickey().c_str()))
        != 0) {
            LOGI("crypto_sign error");
            delete[] buf;
            return false;
        }

        delete[] buf;
    }

    return flag;
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
