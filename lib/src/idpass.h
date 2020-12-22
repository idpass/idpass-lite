/*
 * Copyright (C) 2020 Newlogic Pte. Ltd.
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

#ifdef _WIN32
#define MODULE_API __declspec(dllexport)
#else
#define MODULE_API
#endif

#define ENCRYPTION_KEY_LEN 32
#define SECRET_SIGNATURE_KEY_LEN 64

/**
* Dlib face match threshold values:
*
* DEFAULT_FACEDIFF_FULL - When facial dimension is represented as float[128]
*                         with 4 bytes per float
* DEFAULT_FACEDIFF_HALF - When facial dimension is represented as float[64]
*                         with 2 bytes per float
*/

#define DEFAULT_FACEDIFF_FULL 0.60
#define DEFAULT_FACEDIFF_HALF 0.42

/**
* Standard QR code error correction level setting.
*
* Defaults to ECC_MEDIUM for maximum storage capacity with reasonable
* error correction level for intended use case.
*/

#define ECC_LOW 0
#define ECC_MEDIUM 1
#define ECC_QUARTILE 2
#define ECC_HIGH 3

/**
* Selectable fields in CardDetails structure to appear in public region
* of issued QR code ID. For example, if ACL_SURNAME is selected to be
* visible in the public region, then ACL_SURNAME shall no longer be 
* present in the private region. A successfull card authentication shall
* merge the contents in the private region.
*/

#define DETAIL_SURNAME 1
#define DETAIL_GIVENNAME 2
#define DETAIL_DATEOFBIRTH 4
#define DETAIL_PLACEOFBIRTH 8
#define DETAIL_CREATEDAT 16
#define DETAIL_UIN 32
#define DETAIL_FULLNAME 64
#define DETAIL_GENDER 128
#define DETAIL_POSTALADDRESS 256

#define REVOKED_KEYS "revoked.keys"

/**
* Sub-commands for the ioctl generic function. These are get/set
* functions to alter settings of the calling context. For example,
* IOCTL_SET_ACL sub-command allows for the selection of CardDetails
* fields to be made visible in the public region of the issued ID.
*/

#define IOCTL_SET_FACEDIFF 0x00
#define IOCTL_GET_FACEDIFF 0x01
#define IOCTL_SET_FDIM 0x02
#define IOCTL_GET_FDIM 0x03
#define IOCTL_SET_ECC 0x04
#define IOCTL_SET_ACL 0x05

#define ROOTCA_LEN 160
#define INTERMEDCA_LEN 128

#ifdef __cplusplus
extern "C" {
#endif

/**
* Adds intermediate certificates into the calling context. 
* Cards created, thereafter, shall attached these certificates
* into the issued QR code ID. Intermediate certificates can only
* be added into the calling context having initialized with root certificates.
* 
* @param self Calling context
* @param certs_buf The list of intermediate certificates
* @param certs_buf_len The bytes length of certs_buf
* @return int Returns 0 on success
*/

MODULE_API
int idpass_lite_add_certificates(void* self,
                                 unsigned char* certs_buf,
                                 int certs_buf_len);

/**
* Verifies the fullcard's attached certificate against the root
* certificate configured in the context. Returns 0 if the
* card has no attached certificates. Returns greater than 0 if
* the attached certificates is validated against a root certificate.
* Returns -1 if the attached certificates fails to validate.
*
* @param self Calling context
* @param certs_buf The fullcard bytes content
* @param certs_buf_len The bytes length of certs_buf
@ @return int Either -1, 0, or > 0 
*/

MODULE_API
int idpass_lite_verify_certificate(void* self,
                                   unsigned char* fullcard,
                                   int fullcard_len);

MODULE_API
int idpass_lite_verify_card_signature(void* self,
                                      unsigned char* fullcard,
                                      int fullcard_len, int skipcheckcert);

/**
* A generic function to adjust settings of the calling context.
* It consist of a sub-command prefix by IOCTL_* followed by 
* command-specific parameters. 
*
* @param self Calling context
* @param outlen The count of bytes returned
* @param iobuf The input/output command buffer
* @param iobuf_len The bytes length of iobuf parameter
* @return void* Command-specific returned data buffer
*/

MODULE_API
void* idpass_lite_ioctl(void* self,
                        int* outlen,
                        unsigned char* iobuf,
                        int iobuf_len);

/**
* Explicitely frees up memory blocks returned by context.
*
* @param self Calling context
* @param buf Memory address returned by context
*/

MODULE_API
void idpass_lite_freemem(void* self, void* buf);

/**
* The main initilizationfunction of the library. 
*
* @param keyset_buf The cryptographic key settings for the context.
* @param keyset_buf_len Length of bytes of keyset_buf
* @param rootcerts_buf The root certificates for the context.
* @param rootcerts_buf_len The length of bytes of rootcerts_buf
* @return void* Returns the library context. 
*/

MODULE_API
void* idpass_lite_init(unsigned char* keyset_buf,
                       int keyset_buf_len,
                       unsigned char* rootcerts_buf,
                       int rootcerts_buf_len);

/**
* Returns a QR code ID of a registered identity.
*
* @param self Calling context
* @param outlen Bytes length of returned bytes
* @ident_buf The personal details of the registered identity
* @ident_buf_len Bytes length of ident_buf
* @return Returns an encrypted QR code ID
*/

MODULE_API
unsigned char* idpass_lite_create_card_with_face(void* self,
                                                 int* outlen,
                                                 unsigned char* ident_buf,
                                                 int ident_buf_len);

/**
* Verify user's QR code ID against a matching photo.
*
* @param self Calling context
* @param *outlen Bytes length of returned bytes
* @param encrypted_card The user's QR code ID
* @param encrypted_card_len Bytes length of encrypted_card
* @param photo The ID owner's photo capture
* @param photo_len Length of bytes of photo
* @return Returns the user's CardDetails if there is facial match.
*/

MODULE_API
unsigned char* idpass_lite_verify_card_with_face(void* self,
                                                 int* outlen,
                                                 unsigned char* encrypted_card,
                                                 int encrypted_card_len,
                                                 char* photo,
                                                 int photo_len);
/**
* Verify user's QR code ID against a matching pin.
*
* @param self Calling context
* @param *outlen Bytes length of returned bytes
* @param encrypted_card The user's QR code ID
* @param encrypted_card_len Bytes length of encrypted_card
* @param pin The ID owner's secret pin code
* @return Returns the user's CardDetails if there is pin match.
*/

MODULE_API
unsigned char* idpass_lite_verify_card_with_pin(void* self,
                                                int* outlen,
                                                unsigned char* encrypted_card,
                                                int encrypted_card_len,
                                                const char* pin);
/**
* Signs data with user's QR code ID. 
*
* @param self
* @param outlen Bytes length of returned signature
* @param encrypted_card User's QR code ID
* @param encrypted_card_len Bytes length of encrypted_card
* @param data The input data to be signed
* @param data_len Bytes length of data
* @return Returns the signature
*/

MODULE_API 
int idpass_lite_sign_with_card(void* self,
                               unsigned char* sig,
                               int sig_len,
                               unsigned char* encrypted_card,
                               int encrypted_card_len,
                               unsigned char* data,
                               int data_len);
/**
* Encrypt data with user's QR code ID.
*
* @param self
* @param outlen Bytes length of encrypted data
* @param encrypted_card User's QR code ID.
* @param encrypted_card_len Bytes length of encrypted_card
* @param data The input data to be encrypted
* @param data_len Bytes length of data
* @return The encrypted data
*/

MODULE_API
unsigned char* idpass_lite_encrypt_with_card(void* self,
                                             int* outlen,
                                             unsigned char* encrypted_card,
                                             int encrypted_card_len,
                                             unsigned char* data,
                                             int data_len);

/**
* Returns the QR code bitmap of data.
*
* @param self
* @param data The input data
* @param data_len Bytes lngth of data
* @param *qrsize The square side dimension of QR code 
* @return The bitmap representation of data
*/

MODULE_API
unsigned char* idpass_lite_qrpixel(void* self,
                                   const unsigned char* data,
                                   int data_len,
                                   int* qrsize);
/**
* Returns the QR code bitmap of data.
*
* @param self
* @param *outlen The bytes length of returned data
* @param data The input data
* @param data_len Bytes lngth of data
* @param *qrsize The square side dimension of QR code 
* @return The bitmap representation of data
*/

MODULE_API
unsigned char* idpass_lite_qrpixel2(void* self,
                                    int* outlen,
                                    const unsigned char* data,
                                    int data_len,
                                    int* qrsize);

/**
* Computes full facial dimension of a face.
*
* @param self
* @param photo The face photo
* @param photo_len Bytes length of photo
* @param facearray The float[128] array with 4 bytes per float
* @return Returns count of detected faces in photo
*/

MODULE_API
int idpass_lite_face128d(void* self,
                         char* photo,
                         int photo_len,
                         float* facearray);

/**
* Computes full facial dimension of a face.
*
* @param self
* @param photo The face photo
* @param photo_len Bytes length in photo
* @param buf The facial dimension float[128] as bytes
* @return Returns the count of faces detected in photo
*/

MODULE_API
int idpass_lite_face128dbuf(void* self,
                            char* photo,
                            int photo_len,
                            unsigned char* buf);

/**
* Computes half facial dimension of a face.
*
* @param self
* @param photo The face photo.
* @param photo_len Bytes length of photo
* @param facearray The float[64] with 2 bytes per float
* @return Returns the count of detected faces in photo
*/

MODULE_API
int idpass_lite_face64d(void* self,
                        char* photo,
                        int photo_len,
                        float* facearray);

/**
* Computes half facial dimension of a face.
*
* @param self
* @param photo The face photo.
* @param photo_len Bytes length of photo
* @param facearray The float[64] with 2 bytes per float in byte array format
* @return Returns the count of detected faces in photo
*/

MODULE_API
int idpass_lite_face64dbuf(void* self,
                           char* photo,
                           int photo_len,
                           unsigned char* buf);

/**
 * Asymmetric decryption of a ciphertext using a provided secret key
 *
 * @param self
 * @param outlen The bytes length of decrypted text
 * @param fullcard The QR code ID content
 * @param fullcard_len bytes length of fullcard
 * @param encrypted The encrypted data
 * @param encrypted_len The bytes length of encrypted
 * @return The decrypted text
 */

MODULE_API
unsigned char* idpass_lite_decrypt_with_card(void* self,
                                             int* outlen,
                                             unsigned char* fullcard,
                                             int fullcard_len,
                                             unsigned char* encrypted,
                                             int encrypted_len);

/**
* Generates an AEAD symmetric encryption key.
*
* @param self
* @param key The generated encryption key
* @param key_len The length of generated encryption key
* @return Returns 0 on success
*/

MODULE_API
int idpass_lite_generate_encryption_key(unsigned char* key, int key_len);

/**
* Generates an ED25519 key
*
* @param self
* @param key The generated ED25519 key
* @param key_len The length of generated key
* @return Returns 0 on success
*/

MODULE_API
int idpass_lite_generate_secret_signature_keypair(unsigned char* pk, int pklen, 
    unsigned char* sk, int sklen);

/**
* Generate a self-signed certificate with the provided secretkey.
*
* @param self
* @param skpk The certificates private key
* @param skpk_len The bytes length of skpk
* @param outlen The bytes length of returned self-signed certificate
* @return Returns a self-sign certificate with the provided private key
*/

MODULE_API
unsigned char* idpass_lite_generate_root_certificate(unsigned char* skpk,
                                                     int skpk_len,
                                                     int* outlen);

/**
* Addes the public key into revocation list.
*
* @param self
* @param pubkey The public key to be revocated
* @param pubkey_len Length bytes of pubkey
* @return Returns 0 on success
*/

MODULE_API
int idpass_lite_add_revoked_key(unsigned char* pubkey, int pubkey_len);

/**
* Generate an intermediate certificate with the provided secretkey of signer
* and public key of the intermediate certificate.
*
* @param self
* @param parent_skpk The private key of the signer
* @param parent_skpk_len The length bytes of parent_skpk
* @param child_pubkey The public key of to-be-signed certificate
* @param child_pubkey_len The bytes length of child_pubkey
* @param outlen The bytes length of returned signed intermediate certificate
* @return Returns a signed intermediate certificate
*/

MODULE_API
unsigned char*
idpass_lite_generate_child_certificate(const unsigned char* parent_skpk,
                                       int parent_skpk_len,
                                       const unsigned char* child_pubkey,
                                       int child_pubkey_len,
                                       int* outlen);

/**
* Symmetric decryption of the fullcard QR code ID.
*
* @param self
* @param ecard_buf The fullcard bytes
* @param ecard_buf_len Length bytes of ecard_buf
* @param key The AEAD symmetric decryption key
* @param key_len Length bytes of key
* @return Returns 0 on success and decrypted content stored in ecard_buf
*/

MODULE_API
int idpass_lite_card_decrypt(void* self,
                             unsigned char* ecard_buf,
                             int* ecard_buf_len,
                             unsigned char* key,
                             int key_len);

/**
* Verify the signature of msg using pubkey.
*
* @param self
* @param msg The message 
* @param msg_len Length of message
* @param signature Signature of message
* @param signature_len The length of bytes of signature
* @pubkey Public key that generated the signature
* @pubkey_len Length of bytes of pubkey
* @return Returns 0 if pubkey verifies signature of msg
*/

MODULE_API
int idpass_lite_verify_with_card(void* self,
                                 unsigned char* msg,
                                 int msg_len,
                                 unsigned char* signature,
                                 int signature_len,
                                 unsigned char* pubkey,
                                 int pubkey_len);

/**
*
*
* @param self
* @return
*/

MODULE_API
int idpass_lite_compare_face_photo(void* self,
                                   char* face1,
                                   int face1_len,
                                   char* face2,
                                   int face2_len,
                                   float* fdiff);

/**
* Substracts two faces face1 and face2 and stores result inot fdiff
*
* @param self
* @param face1 The first face input
* @param face1_len Length of face1
* @param face2 The second face input
* @param face2_len Length of face2
* @param fdiff Where to store the computation result
* @return Returns 0 on success subtraction
*/

MODULE_API
int idpass_lite_compare_face_template(unsigned char* face1,
                                      int face1_len,
                                      unsigned char* face2,
                                      int face2_len,
                                      float* fdiff);

/**
* Saves the QR code data into a bitmap file.
*
* @param self
* @param data The QR code content data
* @param data_len Bytes length of data
* @param bitmapfile The output filename
* @return Returns 0 on success file save
*/

MODULE_API
int idpass_lite_saveToBitmap(void* self,
                             unsigned char* data,
                             int data_len,
                             const char* bitmapfile);

/**
* Experimential test of length-prefixed returned blob
*
* @param self Calling context
* @param typ Generic type parameter
* @return Returns a 4 bytes length-prefix byte array
*/

MODULE_API
unsigned char* idpass_lite_uio(void* self,
                               int typ);

MODULE_API
int idpass_lite_compute_hash(unsigned char* data, int data_len, unsigned char* hash, int hash_len);

#ifdef __cplusplus
}
#endif
