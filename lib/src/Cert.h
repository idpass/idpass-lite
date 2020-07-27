#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <list>
#include <random>
#include <sodium.h>
#include <thread>
#include <vector>

class Cert
{
public:
    unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];
    unsigned char privkey[crypto_sign_SECRETKEYBYTES];
    unsigned char signature[crypto_sign_BYTES];
    unsigned char issuerkey[crypto_sign_PUBLICKEYBYTES];
    bool isInTrustedList(std::list<std::array<unsigned char, 32>> &pubkeys);

    /**
     * Returns the certificate object whose pubkey field
     * matches that of the caller's issuerkey field.
     *
     * @param chain - This is a list of certificates
     * @return - Returns a certificate object if a match is
     *           found, or returns nullptr otherwise
     */
    Cert *getIssuer(std::vector<Cert> &chain);

public:
    /**
     * Sign the certificate passed in the cert parameter
     * This class is the signer, and the cert parameter shall be
     * signed. This means, that the public key of this class
     * shall be copied into the cert.issuerkey field.
     *
     * @param cert - This is the certificate to be signed
     */
    void Sign(Cert &cert);

    bool
    Sign(unsigned char *data, int data_len, unsigned char *sig, int sig_len);

    bool isRootCA();
    bool hasValidSignature();

    /**
     * Constructor method for a new certificate instance.
     * If no parameter is supplied, the created certificate
     * shall be self-signed. If an sk parameter is supplied,
     * the created certificate object shall use sk
     * as its private key.
     *
     * @param sk - The masterkey parameter
     */
    Cert(const unsigned char *sk = nullptr);

    bool fromBuffer(unsigned char *buf, int buf_len);
};
