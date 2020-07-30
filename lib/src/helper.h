#pragma once
#ifndef HELPER_H
#define HELPER_H

#ifdef __cplusplus
#include "proto/card_access/card_access.pb.h"

#include <functional>
#include <map>
#include <sstream>
#include <vector>
#include <list>

namespace helper
{
std::vector<std::string> split(std::string& s, char delimiter);
std::map<std::string, std::string> parseToMap(std::string& s);

int dlib_computeface128d(char* photo, int photo_len, unsigned char* f128d);

double
computeFaceDiff(char* photo, int photo_len, const std::string& facearray);

float euclidean_diff(float face1[], float face2[], int n);

bool decryptCard(unsigned char* encrypted_card,
                 int encrypted_card_len,
                 const unsigned char* encryptionKey,
                 const unsigned char* signatureKey,
                 const std::list<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>> &verificationKeys,
                 idpass::SignedIDPassCard&);

bool decryptCard(
    unsigned char* encrypted_card,
    int encrypted_card_len,
    const unsigned char* encryptionKey,
    const unsigned char* signatureKey,
    const std::list<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>>&
        verificationKeys,
    idpass::IDPassCard&);

std::vector<float> get128f(unsigned char* facearray, int facearray_len);

double vectorDistance(float* first, float* last, float* first2);

std::vector<char> readfile(const char* filename);
bool isRevoked(const char* filename, unsigned char* key, int key_len);
bool sign_object(idpass::IDPassCard& object, unsigned char* key, unsigned char* sig);
bool sign_object(idpass::PublicSignedIDPassCard& object,
                       unsigned char* key,
                       unsigned char* sig);
bool sign_object(idpass::CardDetails& object,
                       unsigned char* key,
                       unsigned char* sig);
bool sign_object(std::vector<unsigned char>& blob,
                       unsigned char* key,
                       unsigned char* sig);
int encrypt_object(idpass::SignedIDPassCard& object, unsigned char* key, std::vector<unsigned char>&);
// PublicSignedIDPassCard
bool serialize(idpass::PublicSignedIDPassCard& object, std::vector<unsigned char>&);
bool serialize(idpass::SignedIDPassCard& object,       std::vector<unsigned char>&);
}

#endif // __cplusplus

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void helper_hexdump(const void* data, int size, char* title);
char* helper_readfile(const char* filename, int*);

#ifdef __cplusplus
}
#endif

#endif // HELPER_H
