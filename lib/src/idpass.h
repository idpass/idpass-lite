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

#define ECC_LOW 0
#define ECC_MEDIUM 1
#define ECC_QUARTILE 2
#define ECC_HIGH 3

#define ACL_SURNAME 1
#define ACL_GIVENNAME 2
#define ACL_DATEOFBIRTH 4
#define ACL_PLACEOFBIRTH 8
#define ACL_CREATEDAT 16

#define IOCTL_SET_FACEDIFF 0x00
#define IOCTL_GET_FACEDIFF 0x01
#define IOCTL_SET_FDIM 0x02
#define IOCTL_GET_FDIM 0x03
#define IOCTL_SET_ECC 0x04
#define IOCTL_SET_ACL 0x05

#ifdef __cplusplus
extern "C" {
#endif

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

MODULE_API
void* idpass_api_init(unsigned char* card_encryption_key,
                      int card_encryption_key_len,
                      unsigned char* card_signature_key,
                      int card_signature_key_len,
                      unsigned char* verification_keys,
                      int verification_keys_len);

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
    const char* date_of_birth,
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
 * Compute Dlib byte[128*4] of a given photo
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
 * Compute Dlib byte[64*2] of a given photo
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

MODULE_API
unsigned char* idpass_api_decrypt_with_card(
    void* self,
    int* outlen,
    unsigned char* ciphertext,
    int ciphertext_len,
    unsigned char* skpk,
    int skpk_len);

MODULE_API
int idpass_api_generate_encryption_key( 
    unsigned char *key, int key_len);

MODULE_API 
int idpass_api_generate_secret_signature_key( 
    unsigned char *key, int key_len);

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
