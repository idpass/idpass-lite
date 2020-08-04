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

#define REVOKED_KEYS "revoked.keys"

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
int idpass_lite_add_certificates(void* self,
                                 unsigned char* certs_buf,
                                 int certs_buf_len);

MODULE_API
int idpass_lite_verify_certificate(void* self,
                                   unsigned char* fullcard,
                                   int fullcard_len);

MODULE_API
void* idpass_lite_ioctl(void* self,
                        int* outlen,
                        unsigned char* iobuf,
                        int iobuf_len);

MODULE_API
void idpass_lite_freemem(void* self, void* buf);

MODULE_API
void* idpass_lite_init(unsigned char* cryptokeys_buf,
                       int cryptokeys_buf_len,
                       unsigned char* rootcerts_buf,
                       int rootcerts_buf_len);

MODULE_API
unsigned char* idpass_lite_create_card_with_face(void* self,
                                                 int* outlen,
                                                 unsigned char* ident_buf,
                                                 int ident_buf_len);

MODULE_API
unsigned char* idpass_lite_verify_card_with_face(void* self,
                                                 int* outlen,
                                                 unsigned char* encrypted_card,
                                                 int encrypted_card_len,
                                                 char* photo,
                                                 int photo_len);

MODULE_API
unsigned char* idpass_lite_verify_card_with_pin(void* self,
                                                int* outlen,
                                                unsigned char* encrypted_card,
                                                int encrypted_card_len,
                                                const char* pin);

MODULE_API
unsigned char* idpass_lite_sign_with_card(void* self,
                                          int* outlen,
                                          unsigned char* encrypted_card,
                                          int encrypted_card_len,
                                          unsigned char* data,
                                          int data_len);

MODULE_API
unsigned char* idpass_lite_encrypt_with_card(void* self,
                                             int* outlen,
                                             unsigned char* encrypted_card,
                                             int encrypted_card_len,
                                             unsigned char* data,
                                             int data_len);

MODULE_API
unsigned char* idpass_lite_qrpixel(void* self,
                                   const unsigned char* data,
                                   int data_len,
                                   int* qrsize);

MODULE_API
unsigned char* idpass_lite_qrpixel2(void* self,
                                    int* outlen,
                                    const unsigned char* data,
                                    int data_len,
                                    int* qrsize);

MODULE_API
int idpass_lite_face128d(void* self,
                         char* photo,
                         int photo_len,
                         float* facearray);

MODULE_API
int idpass_lite_face128dbuf(void* self,
                            char* photo,
                            int photo_len,
                            unsigned char* buf);

MODULE_API
int idpass_lite_face64d(void* self,
                        char* photo,
                        int photo_len,
                        float* facearray);

MODULE_API
int idpass_lite_face64dbuf(void* self,
                           char* photo,
                           int photo_len,
                           unsigned char* buf);

MODULE_API
unsigned char* idpass_lite_decrypt_with_card(void* self,
                                             int* outlen,
                                             unsigned char* ciphertext,
                                             int ciphertext_len,
                                             unsigned char* skpk,
                                             int skpk_len);

MODULE_API
int idpass_lite_generate_encryption_key(unsigned char* key, int key_len);

MODULE_API
int idpass_lite_generate_secret_signature_key(unsigned char* key, int key_len);

MODULE_API
unsigned char* idpass_lite_generate_root_certificate(unsigned char* skpk,
                                                     int skpk_len,
                                                     int* outlen);

MODULE_API
int idpass_lite_add_revoked_key(unsigned char* pubkey, int pubkey_len);

MODULE_API
unsigned char*
idpass_lite_generate_child_certificate(const unsigned char* parent_skpk,
                                       int parent_skpk_len,
                                       const unsigned char* child_pubkey,
                                       int child_pubkey_len,
                                       int* outlen);

MODULE_API
int idpass_lite_card_decrypt(void* self,
                             unsigned char* ecard_buf,
                             int* ecard_buf_len,
                             unsigned char* key,
                             int key_len);

MODULE_API
int idpass_lite_verify_with_card(void* self,
                                 unsigned char* msg,
                                 int msg_len,
                                 unsigned char* signature,
                                 int signature_len,
                                 unsigned char* pubkey,
                                 int pubkey_len);

MODULE_API
int idpass_lite_compare_face_photo(void* self,
                                   char* face1,
                                   int face1_len,
                                   char* face2,
                                   int face2_len,
                                   float* fdiff);

MODULE_API
int idpass_lite_compare_face_template(unsigned char* face1,
                                      int face1_len,
                                      unsigned char* face2,
                                      int face2_len,
                                      float* fdiff);

MODULE_API
int idpass_lite_saveToBitmap(void* self,
                             unsigned char* data,
                             int data_len,
                             const char* bitmapfile);

#ifdef __cplusplus
}
#endif
