#include "Cert.h"

bool is_valid_ed25519_key(unsigned char *key)
{
    const char *msg = "attack at dawn!";
    unsigned char signature[crypto_sign_BYTES];
    unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];

    if (0 != crypto_sign_ed25519_sk_to_pk(pubkey, key)) {
        return false;
    }

    if (0
        != crypto_sign_detached(signature,
                                nullptr,
                                reinterpret_cast<const unsigned char *>(msg),
                                std::strlen(msg),
                                key)) {
        return false;
    }

    if (0
        != crypto_sign_verify_detached(
            signature,
            reinterpret_cast<const unsigned char *>(msg),
            std::strlen(msg),
            pubkey)) {
        return false;
    }

    return true;
}

Cert *Cert::getIssuer(std::vector<Cert> &chain, std::vector<Cert> &rootcerts)
{
    unsigned char *pubkey = this->issuerkey;

    // first search into certchain list
    std::vector<Cert>::iterator it
        = std::find_if(chain.begin(), chain.end(), [&pubkey](const Cert &c) {
              if (std::memcmp(c.pubkey, pubkey, 32) == 0)
                  return true;
              return false;
          });

    if (it != chain.end()) {
        return &(*it);
    }

    // if not in certchain list then search into rootCA list
    it = std::find_if(
        rootcerts.begin(), rootcerts.end(), [&pubkey](const Cert &c) {
            if (std::memcmp(c.pubkey, pubkey, 32) == 0)
                return true;
            return false;
        });

    if (it != rootcerts.end()) {
        return &(*it);
    }

    return nullptr;
}

bool Cert::Sign(unsigned char *data,
                int data_len,
                unsigned char *sig,
                int sig_len)
{
    if (sig == nullptr || sig_len != crypto_sign_BYTES) {
        return false;
    }

    if (crypto_sign_detached(sig, nullptr, data, data_len, privkey) != 0) {
        throw std::runtime_error("certificate signing error");
        return false;
    }

    return true;
}

void Cert::Sign(Cert &cert)
{
    std::memcpy(cert.issuerkey, pubkey, crypto_sign_PUBLICKEYBYTES);
    if (crypto_sign_detached(cert.signature,
                             nullptr,
                             cert.pubkey,
                             crypto_sign_PUBLICKEYBYTES,
                             privkey)
        != 0) {
        throw std::runtime_error("certificate signing error");
    }
}

bool Cert::isRootCA()
{
    return std::memcmp(pubkey, issuerkey, crypto_sign_PUBLICKEYBYTES) == 0 ?
               true :
               false;
}

bool Cert::hasValidSignature()
{
    int status;
    // TODO: check pubkey, issuerkey in revoked list
    if ((status = crypto_sign_verify_detached(
             signature, pubkey, crypto_sign_PUBLICKEYBYTES, issuerkey))
        == 0) {
        return true;
    }

    return false;
}

bool Cert::isInTrustedList(std::list<std::array<unsigned char, 32>> &pubkeys)
{
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> rootcapubkey;
    std::copy(
        pubkey, pubkey + crypto_sign_PUBLICKEYBYTES, std::begin(rootcapubkey));

    // Check if is in our trusted list
    if (std::find(pubkeys.begin(), pubkeys.end(), rootcapubkey)
        == pubkeys.end()) {
        return false;
    }

    return true;
}

Cert::Cert(const unsigned char *sk)
{
    int status;
    if (sk) {
        std::memcpy(privkey, sk, crypto_sign_SECRETKEYBYTES);
        status = crypto_sign_ed25519_sk_to_pk(pubkey, sk);
        if (!is_valid_ed25519_key(privkey)) {
            throw std::runtime_error(
                "certificate creation error:invalid ed25519 key");
        }
    } else {
        crypto_sign_keypair(pubkey, privkey);
    }

    std::memcpy(issuerkey, pubkey, crypto_sign_PUBLICKEYBYTES);
    if (crypto_sign_detached(
            signature, nullptr, pubkey, crypto_sign_PUBLICKEYBYTES, privkey)
        != 0) {
        throw std::runtime_error("certificate creation error");
    }
}

bool Cert::fromBuffer(unsigned char *buf, int buf_len)
{
    if (buf_len == 160) {
        /*
        //   bytes layout:
        // - pub/priv key ....... 64
        // - signature .......... 64
        // - issuerkey .......... 32 = 160
        */
        std::memcpy(privkey, buf, crypto_sign_SECRETKEYBYTES);
        if (is_valid_ed25519_key(privkey)) {
            std::memcpy(pubkey,
                        buf + crypto_sign_PUBLICKEYBYTES,
                        crypto_sign_PUBLICKEYBYTES);
            std::memcpy(
                signature, buf + crypto_sign_SECRETKEYBYTES, crypto_sign_BYTES);
            std::memcpy(issuerkey,
                        buf + crypto_sign_SECRETKEYBYTES + crypto_sign_BYTES,
                        crypto_sign_PUBLICKEYBYTES);

            return true;
        }
    } else if (128) {
        /*
        // bytes layout:
        // - pub ................ 32
        // - signature .......... 64
        // - issuerkey .......... 32 = 128
        */
        std::memcpy(pubkey, buf, crypto_sign_PUBLICKEYBYTES);
        std::memcpy(
            signature, buf + crypto_sign_PUBLICKEYBYTES, crypto_sign_BYTES);
        std::memcpy(issuerkey,
                    buf + crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES,
                    crypto_sign_PUBLICKEYBYTES);

        return true;
    }

    return false;
}

std::vector<unsigned char> Cert::toByteArray(bool flag)
{
    std::vector<unsigned char> buf;
    if (flag) {
        std::copy(privkey, privkey + 64, std::back_inserter(buf));
        std::copy(signature, signature + 64, std::back_inserter(buf));
        std::copy(issuerkey, issuerkey + 32, std::back_inserter(buf));
    } else {
        std::copy(pubkey, pubkey + 32, std::back_inserter(buf));
        std::copy(signature, signature + 64, std::back_inserter(buf));
        std::copy(issuerkey, issuerkey + 32, std::back_inserter(buf));
    }
    return buf;
}
