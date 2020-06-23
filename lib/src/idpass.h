#pragma once

#ifdef _WIN32
#define MODULE_API __declspec(dllexport)
#else
#define MODULE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

MODULE_API 
void* idpass_api_ioctl(
    void* self,
    int* outlen,
    unsigned char* input,
    int input_len);

MODULE_API
void idpass_api_freemem(void* self, unsigned char* buf);

MODULE_API
void* idpass_api_init(unsigned char* card_encryption_key,
                      int card_encryption_key_len,
                      unsigned char* card_signature_key,
                      int card_signature_key_len,
                      unsigned char* verification_keys,
                      int verification_keys_len);

//=============
// Description:
// Returns the encrypted protobuf mesage of the card, ie
// an IDPassCard encrypted.
MODULE_API
unsigned char* idpass_api_create_card_with_face(
    void* self,
    int* outlen,
    const char* surname,
    const char* given_name,
    const char* date_of_birth,
    const char* place_of_birth,
    const char* extras,
    char* photo,
    int photo_len,
    const char* pin);

// idpass::CardDetails
MODULE_API
unsigned char* idpass_api_verify_card_with_face(
    void* self,
    int* outlen,
    unsigned char* encrypted_card,
    int encrypted_card_len,
    char* photo,
    int photo_len);

// idpass::CardDetails
MODULE_API
unsigned char* idpass_api_verify_card_with_pin(
    void* self,
    int* outlen,
    unsigned char* encrypted_card,
    int encrypted_card_len,
    const char* pin);

MODULE_API
unsigned char* idpass_api_sign_with_card(
    void* self,
    int* outlen,
    unsigned char* encrypted_card,
    int encrypted_card_len,
    unsigned char* data,
    int data_len);

//=============
// Description:
// This function encrypts the plaintext denoted by 'data' using the
// key denoted by 'encrypted_card'.
// 
// The return value is the ciphertext.
MODULE_API
unsigned char* idpass_api_encrypt_with_card(
    void* self,
    int* outlen,
    unsigned char* encrypted_card,
    int encrypted_card_len,
    unsigned char* data,
    int data_len);

// Returns the qr code bits of square dimension len
MODULE_API
unsigned char* idpass_api_qrpixel(
    void* self,
    const unsigned char* data,
    int data_len,
    int* qrsize);

MODULE_API
int idpass_api_face128d(
    void* self,
    unsigned char* photo,
    int photo_len,
    float* facearray);

MODULE_API
int idpass_api_face128dbuf(
    void* self,
    unsigned char* photo,
    int photo_len,
    unsigned char* buf);

MODULE_API
int idpass_api_face64dbuf(
    void* self,
    unsigned char* photo,
    int photo_len,
    unsigned char* buf);

MODULE_API
int idpass_api_addnum(int a, int b); 

MODULE_API
unsigned char* protobuf_test(
    void* self,
    int* outlen,
    const char* surname,
    const char* given_name,
    const char* date_of_birth,
    const char* place_of_birth,
    const char* extras);

MODULE_API
int idpass_api_saveToBitmap(
    void* self,
    unsigned char* data,
    int data_len,
    const char* bitmapfile);

#ifdef __cplusplus
}
#endif
