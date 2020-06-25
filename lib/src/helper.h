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

bool decryptCard(unsigned char* encrypted_card,
                 int encrypted_card_len,
                 const unsigned char* encryptionKey,
                 const unsigned char* signatureKey,
                 const std::list<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>> &verificationKeys,
                 idpass::SignedIDPassCard&);

std::vector<float> get128f(unsigned char* facearray, int facearray_len);

double vectorDistance(float* first, float* last, float* first2);

std::vector<char> readfile(const char* filename);

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
