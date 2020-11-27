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
#include <array>
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
                 api::KeySet& keyset,
                 idpass::IDPassCard& card,
                 idpass::IDPassCards& fullCard)
{
    if (!fullCard.ParseFromArray(full_card_buf, full_card_buf_len)) {
        return false;
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
        (const unsigned char*)fullCard.signerpublickey().data()) != 0) 
    {
        return false;
    } 

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
    for (auto& pub : keyset.verificationkeys()) {
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
            reinterpret_cast<const unsigned char*>(keyset.encryptionkey().data()))
        != 0) {
        LOGI("decrypt error");
        delete[] privateRegionBuf;
        return false;
    }

    idpass::SignedIDPassCard privateRegion;
    bool flag = privateRegion.ParseFromArray(privateRegionBuf, decrypted_len);

    if (flag) {
        card = privateRegion.card();
    }

    delete[] privateRegionBuf;
    return flag;
}

bool isRevoked(std::list<std::array<unsigned char,32>>& rkeys, unsigned char* key, int key_len)
{
    std::array<char, crypto_sign_PUBLICKEYBYTES> rkey;
    std::copy(key, key + key_len, std::begin(rkey));

    std::list<std::array<unsigned char, 32>>::iterator it =

    std::find_if(rkeys.begin(),
                 rkeys.end(),
                 [&rkey](const std::array<unsigned char, 32>& x) {
                     return std::memcmp(x.data(), rkey.data(), 32) == 0;
                 });

    return it != rkeys.end();
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
#if 0
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
#endif
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
        unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];
        crypto_sign_ed25519_sk_to_pk(pubkey, 
            reinterpret_cast<const unsigned char*>(ckeys.signaturekey().data()));
        // the public part of KeySet::signaturekey is, by default, a 
        // verification key
        api::byteArray* vk = ckeys.mutable_verificationkeys()->Add();
        vk->set_typ(api::byteArray_Typ_ED25519PUBKEY);
        vk->set_val(pubkey, crypto_sign_PUBLICKEYBYTES);
    }

    return true;
}

} // helper

#endif // __cplusplus
