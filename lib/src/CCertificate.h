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
    //api::Certificate value;

    std::vector<unsigned char> m_pk;
    std::vector<unsigned char> m_sk;
    std::vector<unsigned char> m_signature;
    std::vector<unsigned char> m_issuerkey;

public:
    void clear()
    {
        m_sk.clear();
        m_signature.clear();
        m_issuerkey.clear();
        m_pk.clear();
    }

    void setPublicKey(unsigned char* key, int len) 
    {
        if (key == nullptr || len != 32) {
            throw std::logic_error("cert pubkey init error");
        }

        clear();

        m_pk.resize(32);
        std::memcpy(m_pk.data(), key, len);
    }

    CCertificate* getIssuer(std::vector<CCertificate>& chain,
                            std::vector<CCertificate>& rootcerts)
    {
        unsigned char* pubkey = this->m_issuerkey.data();

        // first search into certchain list
        std::vector<CCertificate>::iterator it = std::find_if(
            chain.begin(), chain.end(), [&pubkey](const CCertificate& c) {
                if (std::memcmp(c.m_pk.data(), pubkey, 32) == 0)
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
                if (std::memcmp(c.m_pk.data(), pubkey, 32) == 0)
                    return true;
                return false;
            });

        if (it != rootcerts.end()) {
            return &(*it);
        }

        return nullptr;
    }

    api::Certificate getValue()
    {
        api::Certificate c;

        c.set_pubkey(m_pk.data(), m_pk.size());
        c.set_signature(m_signature.data(), m_signature.size());
        c.set_issuerkey(m_issuerkey.data(), m_issuerkey.size());

        return c;
    }

    bool Sign(CCertificate& cer)
    {
        if (m_sk.size() != 64)
            return false;

        int buf_len = 0;
        unsigned char* buf = idpass_lite_generate_child_certificate(
            m_sk.data(),
            64,
            cer.m_pk.data(),
            32,
            &buf_len);

        api::Certificate retval;

        if (!buf || !retval.ParseFromArray(buf, buf_len)) {
            idpass_lite_freemem(nullptr, buf);
            return false;        
        }

        idpass_lite_freemem(nullptr, buf);

        cer.m_signature.resize(retval.signature().size());
        std::memcpy(cer.m_signature.data(),
                    retval.signature().data(),
                    retval.signature().size());

        cer.m_issuerkey.resize(retval.issuerkey().size());
        std::memcpy(cer.m_issuerkey.data(), 
            retval.issuerkey().data(), retval.issuerkey().size());

        return true;
    }

    CCertificate()
    {
        m_pk.resize(32);
        m_sk.resize(64);

        if (0
            != idpass_lite_generate_secret_signature_keypair(
                m_pk.data(), 32, m_sk.data(), 64)) {
            throw std::logic_error("cert init error");
        }

        int buf_len = 0;
        unsigned char* buf
            = idpass_lite_generate_root_certificate(m_sk.data(), 64, &buf_len);

        api::Certificate retval;
        bool flag = retval.ParseFromArray(buf, buf_len);
        idpass_lite_freemem(nullptr, buf);

        if (!flag) {
            throw std::logic_error("cert init error");
        }

        m_signature.resize(retval.signature().size());
        std::memcpy(m_signature.data(),
                    retval.signature().data(),
                    retval.signature().size());

        m_issuerkey.resize(retval.issuerkey().size());
        std::memcpy(m_issuerkey.data(),
                    retval.issuerkey().data(),
                    retval.issuerkey().size());
    }

    void sign_with_master(unsigned char* sk, int sklen)
    {

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

            api::Certificate retval;

            if (!buffer || !retval.ParseFromArray(buffer, len)) {
                throw std::logic_error("cert init error");
            }

            m_pk.resize(retval.pubkey().size());
            std::memcpy(m_pk.data(), retval.pubkey().data(), m_pk.size());

            m_issuerkey.resize(retval.issuerkey().size());
            std::memcpy(m_issuerkey.data(), retval.issuerkey().data(), m_issuerkey.size());

            m_signature.resize(retval.signature().size());
            std::memcpy(m_signature.data(), retval.signature().data(), m_signature.size());

        } else {
             
        }
    }

    bool parseFrom(unsigned char* buf, int buf_len)
    {
        api::Certificate value;

        if (!value.ParseFromArray(buf, buf_len)) {
            return false;
        }

        clear();

        m_pk.resize(value.pubkey().size());
        m_signature.resize(value.signature().size());
        m_issuerkey.resize(value.issuerkey().size());

        std::memcpy(m_pk.data(), value.pubkey().data(), value.pubkey().size());
        std::memcpy(m_signature.data(), value.signature().data(), value.signature().size());
        std::memcpy(m_issuerkey.data(), value.issuerkey().data(), value.issuerkey().size());

        return true;
    }

    CCertificate(const idpass::Certificate& c)
    {
        if (crypto_sign_verify_detached(
                reinterpret_cast<const unsigned char*>(c.signature().data()),
                reinterpret_cast<const unsigned char*>(c.pubkey().data()),
                crypto_sign_PUBLICKEYBYTES,
                reinterpret_cast<const unsigned char*>(c.issuerkey().data()))
            != 0) {
            throw std::logic_error("certificate anomaly error");
        }

        m_pk.resize(c.pubkey().size());
        std::memcpy(m_pk.data(), c.pubkey().data(), c.pubkey().size());

        m_signature.resize(c.signature().size());
        std::memcpy(m_signature.data(), c.signature().data(), c.signature().size());

        m_issuerkey.resize(c.issuerkey().size());
        std::memcpy(m_issuerkey.data(), c.issuerkey().data(), c.issuerkey().size());

        int siglen = c.signature().size();
        int issuerkeylen = c.issuerkey().size();
        const char* sigbuf = c.signature().data();

        api::Certificate tmp;
        tmp.set_pubkey(m_pk.data(), 32);
        tmp.set_signature(c.signature().data(), 64);
        tmp.set_issuerkey(c.issuerkey().data(), 32);
    }

    CCertificate(const api::Certificate& c)
    {
        if (crypto_sign_verify_detached(
                reinterpret_cast<const unsigned char*>(c.signature().data()),
                reinterpret_cast<const unsigned char*>(c.pubkey().data()),
                crypto_sign_PUBLICKEYBYTES,
                reinterpret_cast<const unsigned char*>(c.issuerkey().data()))
            != 0) {
            throw std::logic_error("certificate anomaly error");
        }

        m_pk.resize(c.pubkey().size());
        std::memcpy(m_pk.data(), c.pubkey().data(), c.pubkey().size());

        m_signature.resize(c.signature().size());
        std::memcpy(m_signature.data(), c.signature().data(), c.signature().size());

        m_issuerkey.resize(c.issuerkey().size());
        std::memcpy(m_issuerkey.data(), c.issuerkey().data(), c.issuerkey().size());
    }

    bool hasValidSignature()
    {
        if (crypto_sign_verify_detached(
            m_signature.data(),
                m_pk.data(),
                crypto_sign_PUBLICKEYBYTES,
                m_issuerkey.data())
            != 0) {
            return false;
        }

        return true;
    }

    bool isSelfSigned()
    {
        return std::memcmp(m_pk.data(), m_issuerkey.data(), 32)
               == 0;
    }
};
