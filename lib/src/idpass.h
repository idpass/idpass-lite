/**
 * The `idpass_api_qrpixel` function uses the implementation in:
 * https://github.com/ricmoo/QRCode (Copyright (c) 2017 Richard Moore)
 *
 */

#pragma once

#ifdef _WIN32
#define MODULE_API __declspec(dllexport)
#else
#define MODULE_API
#endif

#define ENCRYPTION_KEY_LEN 32
#define SECRET_SIGNATURE_KEY_LEN 64

#define DEFAULT_FACEDIFF_FULL 0.60
#define DEFAULT_FACEDIFF_HALF 0.42

/**
 * The error correction settings when generating 
 * a QR code. The library defaults to ECC_MEDIUM but
 * can be later change via an ioctl function. The
 * default setting of ECC_MEDIUM is optimal for a 
 * QR code ID and there should be no need to change
 * this default setting. 
 *
 * Below is a guideline that describes the 
 * various settings practically applicable:
 * https://www.qrcode.com/en/about/error_correction.html#:~:text=To%20select%20error%20correction%20level,the%20large%20amount%20of%20data
 */
#define ECC_LOW 0
#define ECC_MEDIUM 1
#define ECC_QUARTILE 2
#define ECC_HIGH 3

/**
 * These bit flags are used to toggle the visibility of 
 * the corresponding card details field using the 
 * ioctl command.
 */
#define ACL_SURNAME 1
#define ACL_GIVENNAME 2
#define ACL_DATEOFBIRTH 4
#define ACL_PLACEOFBIRTH 8
#define ACL_CREATEDAT 16

#define REVOKED_KEYS "revoked.keys"

/**
 * These are the supported ioctl commands used to
 * get/set certain parmeters:
 * IOCTL_SET_FACEDIFF - Sets the floating point threshold value 
 * used to match face templates.
 *
 * IOCTL_GET_FACEDIFF - Gets the floating point threshold value
 * used to match face templates.
 *
 * IOCTL_SET_FDIM - Toggles between full mode or half mode when
 * computing the facial biometry.
 *
 * IOCTL_GET_FDIM - Gets current mode either full or half mode
 * used when computing the facial biometry.
 *
 * IOCTL_SET_ECC - Change the QR code error correction code level.
 *
 * IOCTL_SET_ACL - Toggles card details field visibility in the
 * returned public section of the QR code.
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

MODULE_API
int idpass_api_add_certificates(void* self,
                             unsigned char** certificates,
                             int *len,
                             int ncertificates);

/**
 * A generalized I/O function used to get/set settings
 * @param outlen Count of returned bytes
 * @param iobuf Input/Output command buffer
 * @param iobuf_len Command buffer length
 * @return Command-related output bytes
 */
MODULE_API 
void* idpass_api_ioctl(
    void* self,
    int* outlen,
    unsigned char* iobuf,
    int iobuf_len);

/**
 * Used to explicitly free the bytes returned by the library
 * @param buf Address of buffer
 */
MODULE_API
void idpass_api_freemem(void* self, void* buf);

/**
 * The main initialization function of the library. This is used
 * to set the needed cryptographic keys. 
 * @param card_encryption_key An AEAD symmetric key used to encrypt the
 *        private contents of the QR code ID. The documentation of this
 *        key type can be found in: 
 *        https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction
 * @param card_encryption_key_len The length in bytes of the 
 *        card_encryption_key. An IETF chacha20 poly1305 key has a length
 *        of 32 bytes.
 * @param card_signaturekey An ED25519 signature key used to sign every content
 *        both public and private of the QR code.
 * @param card_signaturekey_len The length in bytes of card_signaturekey. An ED25519
 *        signature key has a length of 64 bytes.
 * @param verification_keys A list of public keys used to verify the signature
 *        of the contents in the QR code ID. Each public key has a length of 
 *        32 bytes.
 * @param verification_keys_len The total length in bytes of verification_keys 
 *        parameter
 * @return Returns an instance context of the library
 */

MODULE_API
void* idpass_api_init(unsigned char* card_encryption_key,
                      int card_encryption_key_len,
                      unsigned char* card_signature_key,
                      int card_signature_key_len,
                      unsigned char* verification_keys,
                      int verification_keys_len,
                      unsigned char** certificates,
                      int* len,
                      int ncertificates);

/**
 * Creates a new card with the given personal details
 * @param outlen Length of returned bytes
 * @param surname Surname of person
 * @param given_name Givenname of person
 * @param date_of_birth Date of birth (1980/12/17)
 * @param place_of_birth Birthplace of person
 * @param pin Secret pin code of the person
 * @param photo The bytes of person's photo
 * @param photo_len Length of bytes
 * @param pub_extras_buf idpass::Dictionary serialized for public KV extras
 * @param pub_extras_buf_len Count of bytes
 * @param priv_extras_buf idpass::Dictionary serialized for private KV extras
 * @param priv_extras_buf_len Count of bytes
 * @return Returns idpass::IDPassCards containing public/private components
 */
MODULE_API
unsigned char* idpass_api_create_card_with_face(
    void* self,
    int* outlen,
    const char* surname,
    const char* given_name,
    unsigned char* date_of_birth,
    int date_of_birth_len,
    const char* place_of_birth,
    const char* pin,
    char* photo,
    int photo_len,
    unsigned char* pub_extras_buf,
    int pub_extras_buf_len,
    unsigned char* priv_extras_buf,
    int priv_extras_buf_len);

/**
 * Unlocks the encrypted_card using photo
 * @param outlen Count of returned bytes
 * @param encrypted_card owner's encrypted component ID
 * @param encrypted_card_len Count of bytes
 * @param photo Content bytes of owner photo
 * @param photo_len Count of bytes
 * @return Protobuf serialized of idpass::CardDetails
 */
MODULE_API
unsigned char* idpass_api_verify_card_with_face(
    void* self,
    int* outlen,
    unsigned char* encrypted_card,
    int encrypted_card_len,
    char* photo,
    int photo_len);

/**
 * Unlocks the encrypted_card using owner's pin code
 * @param outlen Count of returned bytes
 * @param encrypted_card owner's encrypted component ID
 * @param encrypted_card_len Count of bytes
 * @param pin Owner's secret pin code
 * @return Protobuf serialized of idpass::CardDetails
 */
MODULE_API
unsigned char* idpass_api_verify_card_with_pin(
    void* self,
    int* outlen,
    unsigned char* encrypted_card,
    int encrypted_card_len,
    const char* pin);

/**
 * Returns a signature of input data
 * @param outlen Count bytes of returned data
 * @param encrypted_card Card owner's private component
 * @param encrypted_card_len Count of bytes
 * @param data The data that is to be signed
 * @param data_len Count of bytes
 * @return The digital signature
 */
MODULE_API
unsigned char* idpass_api_sign_with_card(
    void* self,
    int* outlen,
    unsigned char* encrypted_card,
    int encrypted_card_len,
    unsigned char* data,
    int data_len);

/**
 * This function encrypts the plaintext denoted by data using the
 * ED25519 key inside encrypted_card
 * @param outlen Count of bytes encrypted data
 * @param encrypted_card Owner's encrypted component 
 * @param encrypted_card_len Count of bytes
 * @param data The input data to be encrypted
 * @param data_len Length bytes 
 * @return The ciphertext
 */
MODULE_API
unsigned char* idpass_api_encrypt_with_card(
    void* self,
    int* outlen,
    unsigned char* encrypted_card,
    int encrypted_card_len,
    unsigned char* data,
    int data_len);

/**
 * Returns QR Code represented as pixel  bits
 * @param data The data to be encoded as QR Code
 * @param data_len Count of bytes
 * @param qrsize The square side dimension of QR Code
 * @return The QR Code representation of data
 */
MODULE_API
unsigned char* idpass_api_qrpixel(
    void* self,
    const unsigned char* data,
    int data_len,
    int* qrsize);

/**
 * Returns QR Code represented as pixel  bits. This
 * is for the Python ctypes API to easily extract the returned
 * bytes using the outlen length via: buf = string_at(buf,buflen)
 * @param outlen The length of the returned bytes
 * @param data The data to be encoded as QR Code
 * @param data_len Count of bytes
 * @param qrsize The square side dimension of QR Code
 * @return The QR Code representation of data
 */
MODULE_API
unsigned char* idpass_api_qrpixel2(
    void* self,
    int* outlen,
    const unsigned char* data,
    int data_len,
    int* qrsize);

/**
 * Compute Dlib float[128] of a given photo
 * @param photo Any photo
 * @param photo_len Length bytes of photo
 * @param facearray Dlib 128 dimension of one face
 * @return Count of faces detected by Dlib
 */
MODULE_API
int idpass_api_face128d(
    void* self,
    char* photo,
    int photo_len,
    float* facearray);

/**
 * Compute Dlib byte[128*4] of a given photo.
 * The computed face template is represented
 * as a byte array.
 * @param photo Any photo
 * @param photo_len Length bytes of photo
 * @param buf Dlib dimension of one face as bytes
 * @return Count of faces detected by Dlib
 */
MODULE_API
int idpass_api_face128dbuf(
    void* self,
    char* photo,
    int photo_len,
    unsigned char* buf);

/**
 * Compute Dlib float[64] of a given photo. The
 * computed face template is represented as 
 * 64 floats with 2 bytes per float.
 * @param photo Any photo
 * @param photo_len Length bytes of photo
 * @param buf Dlib dimension of one face as bytes
 * @return Count of faces detected by Dlib
 */
MODULE_API
int idpass_api_face64d(
    void* self,
    char* photo,
    int photo_len,
    float* facearray);

/**
 * Compute Dlib byte[64*2] of a given photo. The
 * computed face template is represented as
 * array of bytes.
 * @param photo Any photo
 * @param photo_len Length bytes of photo
 * @param buf Dlib dimension of one face as bytes
 * @return Count of faces detected by Dlib
 */
MODULE_API
int idpass_api_face64dbuf(
    void* self,
    char* photo,
    int photo_len,
    unsigned char* buf);

/**
 * This is used to decrypt a ciphertext using
 * a symmetric key.
 * @param self - Library context
 * @param outlen - Describes length of returned bytes
 * @param ciphertext - The ciphertext to be decrypted
 * @param ciphertext_len - Describes the length of ciphertext
 * @param skpk - The symmetric key used for decryption
 * @param skpk_len - Describes the length of skpk
 * @return - Returns the plaintext upon successful decryption
 * or NULL otherwise.
 */
MODULE_API
unsigned char* idpass_api_decrypt_with_card(
    void* self,
    int* outlen,
    unsigned char* ciphertext,
    int ciphertext_len,
    unsigned char* skpk,
    int skpk_len);

/**
 * 
 *
 */
MODULE_API
int idpass_api_generate_encryption_key( 
    unsigned char *key, int key_len);

MODULE_API 
int idpass_api_generate_secret_signature_key( 
    unsigned char *key, int key_len);

MODULE_API
int idpass_api_generate_root_certificate(unsigned char* skpk,
                                         int skpk_len,
                                         unsigned char* buf,
                                         int buf_len);

MODULE_API 
int idpass_api_add_revoked_key( 
    unsigned char *pubkey, int pubkey_len);

MODULE_API
int idpass_api_generate_child_certificate(unsigned char* parent_skpk,
                                          int parent_skpk_len,
                                          unsigned char* child_pubkey,
                                          int child_pubkey_len,
                                          unsigned char* buf,
                                          int buf_len);

MODULE_API
int idpass_api_card_decrypt(
    void* self,
    unsigned char* ecard_buf,
    int *ecard_buf_len,
    unsigned char *key,
    int key_len);

MODULE_API
int idpass_api_verify_with_card(
    void* self,
    unsigned char* msg,
    int msg_len,
    unsigned char* signature,
    int signature_len,
    unsigned char* pubkey,
    int pubkey_len);

// return the matching score beween the 2 faces/templates
MODULE_API
int idpass_api_compare_face_photo(void* self,
                                  char* face1,
                                  int face1_len,
                                  char* face2,
                                  int face2_len,
                                  float* fdiff); 

MODULE_API
int idpass_api_compare_face_template(unsigned char* face1,
                                     int face1_len,
                                     unsigned char* face2,
                                     int face2_len,
                                     float* fdiff);

/**
 * Test function
 */
MODULE_API
int idpass_api_addnum(int a, int b); 


/**
 * Test function
 */
MODULE_API
unsigned char* protobuf_test(
    void* self,
    int* outlen,
    const char* surname,
    const char* given_name,
    const char* date_of_birth,
    const char* place_of_birth,
    const char* extras);

/**
 * Helper function to save QR Code as bitmap
 * @param data The input data to be encoded into QR code
 * @param data_len Length bytes of data
 * @param bitmapfile The full path where to save the bitmap
 * @return Returns 0 on success
 */
MODULE_API
int idpass_api_saveToBitmap(
    void* self,
    unsigned char* data,
    int data_len,
    const char* bitmapfile);

#ifdef __cplusplus
}
#endif
