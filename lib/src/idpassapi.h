
#ifdef __cplusplus
extern "C" {
#endif

void* idpass_api_init(unsigned char* card_encryption_key,
                      unsigned char* card_signature_key,
                      unsigned char* verification_keys,
                      int count);

int idpass_api_saveToBitmap(void* self, 
		unsigned char* data, int data_len, const char* bitmapfile);

// Returns the qr code bits of square dimension len
unsigned char* idpass_api_qrpixel(void* self,
    const unsigned char* data, int data_len, int* qrsize);

// Idpass__CardDetails*
unsigned char* idpass_api_verify_card_with_face(void* self,
                                                int* outlen,
                                                unsigned char* encrypted_card,
                                                int encrypted_card_len,
                                                char* photo,
                                                int photo_len);

// Idpass__CardDetails*
unsigned char* idpass_api_verify_card_with_pin(void* self,
                                               int* outlen,
                                               unsigned char* encrypted_card,
                                               int encrypted_card_len,
                                               const char* pin);

/*
Description:
This function encrypts the plaintext denoted by 'data' using the
key denoted by 'encrypted_card'.

The return value is the ciphertext.*/
unsigned char* idpass_api_encrypt_with_card(void* self,
                                            int* outlen,
                                            unsigned char* encrypted_card,
                                            int encrypted_card_len,
                                            unsigned char* data,
                                            int data_len);

unsigned char* idpass_api_sign_with_card(void* self,
                                         int* outlen,
                                         unsigned char* encrypted_card,
                                         int encrypted_card_len,
                                         unsigned char* data,
                                         int data_len);

/*
 Description:
 Returns the encrypted protobuf mesage of the card, ie
 an IDPassCard encrypted.*/
unsigned char* idpass_api_create_card_with_face(void* self,
                                                int* outlen,
                                                const char* surname,
                                                const char* given_name,
                                                const char* date_of_birth,
                                                const char* place_of_birth,
                                                const char* extras,
                                                char* photo,
                                                int photo_len,
                                                const char* pin);

int idpass_api_face128d(void* self,
                        unsigned char* photo,
                        int photo_len,
                        float* facearray);

int idpass_api_face128dbuf(void* self,
                        unsigned char* photo,
                        int photo_len,
                        unsigned char* buf);

int idpass_api_face64dbuf(void* self,
                        unsigned char* photo,
                        int photo_len,
                        unsigned char* buf);

int idpass_api_addnum(int a, int b); // test function

unsigned char* protobuf_test(void* self,
                             int* outlen,
                             const char* surname,
                             const char* given_name,
                             const char* date_of_birth,
                             const char* place_of_birth,
                             const char* extras);


#ifdef __cplusplus
}
#endif
