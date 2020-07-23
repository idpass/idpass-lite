#include "Cert.h"

unsigned char masterkey[] = {
    0x2d, 0x52, 0xf8, 0x6a, 0xaa, 0x4d, 0x62, 0xfc, 0xab, 0x4d, 0xb0,
    0x0a, 0x21, 0x1a, 0x12, 0x60, 0xf8, 0x17, 0xc5, 0xf2, 0xba, 0xb7,
    0x3e, 0xfe, 0xd6, 0x36, 0x07, 0xbc, 0x9d, 0xb3, 0x96, 0xee, 0x57,
    0xc6, 0x33, 0x09, 0xfa, 0xc2, 0x1b, 0x60, 0x04, 0x76, 0x4e, 0xf6,
    0xf7, 0xc6, 0x2f, 0x28, 0xcf, 0x63, 0x40, 0xbe, 0x13, 0x10, 0x6e,
    0x80, 0xed, 0x70, 0x41, 0x8f, 0xa1, 0xb9, 0x27, 0xb4};

Cert *Cert::getIssuer(std::vector<Cert> &chain) {
  unsigned char *pubkey = this->issuerkey;

  std::vector<Cert>::iterator it =
      std::find_if(chain.begin(), chain.end(), [&pubkey](const Cert &c) {
        if (std::memcmp(c.pubkey, pubkey, 32) == 0)
          return true;
        return false;
      });

  if (it != chain.end()) {
    return &(*it);
  }

  return nullptr;
}

void Cert::Sign(Cert &cert) {
  std::memcpy(cert.issuerkey, pubkey, crypto_sign_PUBLICKEYBYTES);
  if (crypto_sign_detached(cert.signature, nullptr, cert.pubkey,
                           crypto_sign_PUBLICKEYBYTES, privkey) != 0) {
    throw std::runtime_error("certificate signing error");
  }
}

bool Cert::isRootCA() {
  return std::memcmp(pubkey, issuerkey, crypto_sign_PUBLICKEYBYTES) == 0
             ? true
             : false;
}

bool Cert::hasValidSignature() {
  // do we need to have a list of revoked intermediateCA pubkeys ?
  // for rootCA pubkeys definitely we need to have

  if (crypto_sign_verify_detached(signature, pubkey, crypto_sign_PUBLICKEYBYTES,
                                  issuerkey) == 0) {
    // if rootCA, then it's privkey must be in the list of active
    // masterkeys otherwise, it's an impostor or revoked rootCA
    if (isRootCA()) {
      if (std::memcmp(privkey, masterkey, crypto_sign_SECRETKEYBYTES) != 0) {
        return false;
      }
    }

    return true;
  }

  return false;
}

Cert::Cert(const unsigned char *sk) {
  if (sk) {
    std::memcpy(privkey, sk, crypto_sign_SECRETKEYBYTES);
    crypto_sign_ed25519_sk_to_pk(pubkey, sk);
  } else {
    crypto_sign_keypair(pubkey, privkey);
  }
  std::memcpy(issuerkey, pubkey, crypto_sign_PUBLICKEYBYTES);
  if (crypto_sign_detached(signature, nullptr, pubkey,
                           crypto_sign_PUBLICKEYBYTES, privkey) != 0) {
    throw std::runtime_error("certificate creation error");
  }
}

bool verify_chain(std::vector<Cert> &chain, Cert *certificate,
                  unsigned char *pOrigin, int depth) {
  bool flag = false;

  if (!certificate) {
    for (Cert &cert : chain) {
      if (!verify_chain(chain, &cert, pOrigin, depth + 1)) {
        return false;
      }
    }
    return true;
  }

  if (pOrigin == nullptr) {
    pOrigin = new unsigned char[32];
    std::memcpy(pOrigin, certificate->pubkey, 32);
  } else {
    if (std::memcmp(pOrigin, certificate->pubkey, 32) == 0) {
      return false; // detected circular chain
    }
  }

  if (certificate->hasValidSignature()) {
    if (!certificate->isRootCA()) {
      Cert *issuerCert = certificate->getIssuer(chain);
      if (issuerCert) {
        flag = verify_chain(chain, issuerCert, pOrigin, depth + 1);
      }
    } else {
      flag = true;
    }
  }

  if (pOrigin && depth == 1) {
    delete[] pOrigin;
  }

  return flag;
}
