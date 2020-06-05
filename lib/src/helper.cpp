#include "sodium.h"
#include "bin16.h"

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus

#include "dlibapi.h"
#include "protogen/card_access.pb.h"

#include <cmath>
#include <fstream>
#include <ios>
#include <map>
#include <sstream>
#include <vector>

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

        if (buf_len == 128 * 4) {
            bin16::f4b_to_f4(buf, 128 * 4, input_f4);
            // calculate vector distance
            face_diff = [&input_f4, &F4]() {
                double ret = 0.0;
                for (int i = 0; i < 128; i++) {
                    double dist = static_cast<double>(input_f4[i]) - static_cast<double>(F4[i]);
                    ret += dist * dist;
                }
                return ret > 0.0 ? sqrt(ret) : 0.0;
            }();
        } else {
            float photoFace[128];
            bin16::f4_to_f2(F4, 128, photoFace);
            float cardAccessFace[64];
            bin16::f2b_to_f2(buf, buf_len, cardAccessFace);

            // calculate vector distance
            face_diff = [&cardAccessFace, &photoFace]() {
                double ret = 0.0;
                for (int i = 0; i < 64; i++) { // only the first 64
                    double dist = static_cast<double>(cardAccessFace[i])
                                  - static_cast<double>(photoFace[i]);
                    ret += dist * dist;
                }
                return ret > 0.0 ? sqrt(ret) : 0.0;
            }();
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
                 unsigned char* encryptionKey,
                 idpass::SignedIDPassCard& ecard)
{
    unsigned char* cardserialized
        = new unsigned char[encrypted_card_len
                            - crypto_aead_chacha20poly1305_IETF_NPUBBYTES];

    unsigned long long decrypted_len;

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    std::memcpy(
        nonce, encrypted_card, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);

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
        return false;
    }

    bool flag = ecard.ParseFromArray(cardserialized, decrypted_len);
    delete[] cardserialized;
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