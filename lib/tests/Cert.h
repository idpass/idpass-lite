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

class Cert {
private:
  unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];
  unsigned char privkey[crypto_sign_SECRETKEYBYTES];
  unsigned char signature[crypto_sign_BYTES];
  unsigned char issuerkey[crypto_sign_PUBLICKEYBYTES];

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
   * Recursively follow through the chain until arriving at
   * a trusted rootCA.
   */
  friend bool verify_chain(std::vector<Cert> &, Cert *, unsigned char *, int);

  /**
   * Sign the certificate passed in the cert parameter
   * This class is the signer, and the cert parameter shall be
   * signed. This means, that the public key of this class
   * shall be copied into the cert.issuerkey field.
   * 
   * @param cert - This is the certificate to be signed
   */
  void Sign(Cert &cert);

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
};

/**
 * If only the chain parameter is supplied, then verify_chain() shall iterate 
 * each Cert element in the list and validate each it to a trusted rootCA. 
 * If it encounters one certificate that is invalid, then it returns false
 * and no longer continues processing the rest of the certificates in the list.
 * If it returns true then it means every certificate in the list is verifiable.
 * There is no implied order of the Certificate elements in this list, the rootCA
 * can be the first element, it can be in the middle of the list or at the last element 
 * in the list.
 * 
 * If the certificate parameter is supplied, then this function shall only verify
 * this particular certificate. It does this by following through its chain until arriving
 * at a recognized rootCA. The list can contain invalid or revoked certificate entries but
 * this function can still verify a particular certificate provided that the required 
 * chain traversal in every step of the way are all valid. 
 *
 * @param chain - This is a list of certificates with no implied order. Certificates can
          be added or deleted.
 * @param certificate - Validate only this particular certificate
 * @param pOrigin - This is an internal implementation house keeping used to
 *        deal with circular certificate chain. Please see the test case for this.
 * @param depth - This is an internal implementation house keeping used to deal
 *        with circular certificate chain.
 * @return True means every certificate in the chain are valid and verifiable. Or
           the particular supplied certificate is valid and verifiable.
 */
bool verify_chain(std::vector<Cert> &chain, Cert *certificate = nullptr,
                  unsigned char *pOrigin = nullptr, int depth = 0);

extern unsigned char masterkey[];
