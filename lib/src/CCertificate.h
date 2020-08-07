#pragma once
#include "idpass.h"
#include "proto/api/api.pb.h"
#include "proto/idpasslite/idpasslite.pb.h"

#include <algorithm>
#include <sodium.h>
#include <vector>

class CCertificate
{
public:
    api::Certificate value;

public:
    void setPublicKey(unsigned char* key, int len) 
    {
        if (key == nullptr || len != 32) {
            throw std::logic_error("cert pubkey init error");
        }

        value.Clear();
        value.set_pubkey(key, len);
    }

    bool hasPrivateKey()
    {
        return value.privkey().size() > 0;
    }

    CCertificate* getIssuer(std::vector<CCertificate>& chain,
                            std::vector<CCertificate>& rootcerts)
    {
        const char* pubkey = this->value.issuerkey().data();

        // first search into certchain list
        std::vector<CCertificate>::iterator it = std::find_if(
            chain.begin(), chain.end(), [&pubkey](const CCertificate& c) {
                if (std::memcmp(c.value.pubkey().data(), pubkey, 32) == 0)
                    return true;
                return false;
            });

        if (it != chain.end()) {
            return &(*it);
        }

        // if not in certchain list then search into rootCA list
        it = std::find_if(
            rootcerts.begin(),
            rootcerts.end(),
            [&pubkey](const CCertificate& c) {
                if (std::memcmp(c.value.pubkey().data(), pubkey, 32) == 0)
                    return true;
                return false;
            });

        if (it != rootcerts.end()) {
            return &(*it);
        }

        return nullptr;
    }

    api::Certificate getValue(bool flag = false)
    {
        api::Certificate c;//
        c.CopyFrom(value);
        if (!flag) {
            c.clear_privkey();
        }
        return c;
    }

    bool Sign(CCertificate& cer)
    {
        if (value.privkey().size() != 64) {
            /* a certificate a without private key cannot sign another
             * certificate */
            return false;
        }

        int buf_len = 0;
        unsigned char* buf = idpass_lite_generate_child_certificate(
            reinterpret_cast<const unsigned char*>(value.privkey().data()),
            64,
            reinterpret_cast<const unsigned char*>(cer.value.pubkey().data()),
            32,
            &buf_len);

        api::Certificate ccc;
        ccc.ParseFromArray(buf, buf_len);

        cer.value.set_signature(ccc.signature().data(), ccc.signature().size());
        cer.value.set_issuerkey(ccc.issuerkey().data(), ccc.issuerkey().size());

        return true;
    }

    CCertificate()
    {
        unsigned char privkey[64];
        idpass_lite_generate_secret_signature_key(privkey, 64);

        int buf_len = 0;
        unsigned char* buf
            = idpass_lite_generate_root_certificate(privkey, 64, &buf_len);
        value.ParseFromArray(buf, buf_len);
    }

    CCertificate(unsigned char* skpk, int skpk_len)
    {
        if (skpk == nullptr || skpk_len != 64) {
            throw std::logic_error("cert init error");
        }
        if (skpk_len == 64) {
            unsigned char privkey[64];
            std::memcpy(privkey, skpk, skpk_len);

            int len = 0;
            unsigned char* buffer
                = idpass_lite_generate_root_certificate(privkey, 64, &len);
            value.ParseFromArray(buffer, len);
        } else {
             
        }
    }

    bool parseFrom(unsigned char* buf, int buf_len)
    {
        if (!value.ParseFromArray(buf, buf_len)) {
            return false;
        }

        return true;
    }

    CCertificate(const idpass::Certificate& c)
    {
        unsigned char pubkey[32];
        std::memcpy(pubkey, c.pubkey().data(), 32);

        int siglen = c.signature().size();
        int issuerkeylen = c.issuerkey().size();
        const char* sigbuf = c.signature().data();

        if (crypto_sign_verify_detached(
                reinterpret_cast<const unsigned char*>(c.signature().data()),
                pubkey,
                crypto_sign_PUBLICKEYBYTES,
                reinterpret_cast<const unsigned char*>(c.issuerkey().data()))
            != 0) {
            throw std::logic_error("certificate anomaly error");
        }

        api::Certificate tmp;
        tmp.clear_privkey();
        tmp.set_pubkey(pubkey, 32);
        tmp.set_signature(c.signature().data(), 64);
        tmp.set_issuerkey(c.issuerkey().data(), 32);

        value.CopyFrom(tmp);
        //value = tmp;
    }

    CCertificate(const api::Certificate& c)
    {
        unsigned char pubkey[32];

        if (c.privkey().size() == 64) {
            crypto_sign_ed25519_sk_to_pk(
                pubkey,
                reinterpret_cast<const unsigned char*>(c.privkey().data()));
            if (std::memcmp(pubkey, c.pubkey().data(), 32) != 0) {
                throw std::logic_error("certificate anomaly error");
            }
        } else {
            std::memcpy(pubkey, c.pubkey().data(), 32);
        }

        if (crypto_sign_verify_detached(
                reinterpret_cast<const unsigned char*>(c.signature().data()),
                pubkey,
                crypto_sign_PUBLICKEYBYTES,
                reinterpret_cast<const unsigned char*>(c.issuerkey().data()))
            != 0) {
            throw std::logic_error("certificate anomaly error");
        }

        value.CopyFrom(c);
    }

    bool hasValidSignature()
    {
        unsigned char pubkey[32];

        if (value.privkey().size() == 64) {
            crypto_sign_ed25519_sk_to_pk(
                pubkey,
                reinterpret_cast<const unsigned char*>(value.privkey().data()));
            if (std::memcmp(pubkey, value.pubkey().data(), 32) != 0) {
                return false;
            }
        } else {
            std::memcpy(pubkey, value.pubkey().data(), 32);
        }

        if (crypto_sign_verify_detached(reinterpret_cast<const unsigned char*>(
                                            value.signature().data()),
                                        pubkey,
                                        crypto_sign_PUBLICKEYBYTES,
                                        reinterpret_cast<const unsigned char*>(
                                            value.issuerkey().data()))
            != 0) {
            return false;
        }

        return true;
    }

    bool isSelfSigned()
    {
        return std::memcmp(value.pubkey().data(), value.issuerkey().data(), 32)
               == 0;
    }
};