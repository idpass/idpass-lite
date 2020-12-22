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

#include "bin16.h"

#include <cstring>

void bin16::f4_to_f4b(float* f4, int f4_len, unsigned char* f4b)
{
    for (int i = 0; i < f4_len; i++) {
        std::memcpy(f4b + i * 4, &f4[i], 4);
    }
}

void bin16::f4_to_f2b(float* f4, int f4_len, unsigned char* f2b)
{
    unsigned short hf;
    for (int i = 0; i < f4_len; i++) {
        hf = float_to_half(f4[i]);
        std::memcpy(f2b + i * 2, &hf, 2);
    }
}

void bin16::f4_to_f2(float* f4, int f4_len, float* f2)
{
    unsigned short hf;
    for (int i = 0; i < f4_len; i++) {
        hf = float_to_half(f4[i]);
        f2[i] = half_to_float(hf);
    }
}

void bin16::f4b_to_f2(unsigned char* float4buf, int float4buf_len, float* f2)
{
    float f;
    unsigned short hf;
    for (int i = 0; i < float4buf_len / 4; i++) {
        std::memcpy(&f, float4buf + i * 4, 4);
        hf = float_to_half(f);
        f2[i] = half_to_float(hf);
    }
}

void bin16::f2b_to_f2(unsigned char* float2buf, int float2buf_len, float* f2)
{
    float f;
    unsigned short hf;
    for (int i = 0; i < float2buf_len / 2; i++) {
        std::memcpy(&hf, float2buf + i * 2, 2);
        f = half_to_float(hf);
        f2[i] = f;
    }
}

void bin16::f4b_to_f4(unsigned char* float4buf, int float4buf_len, float* f4)
{
    float f;
    for (int i = 0; i < float4buf_len / 4; i++) {
        std::memcpy(&f, float4buf + i * 4, 4);
        f4[i] = f;
    }
}

void bin16::f2b_to_f4(unsigned char* f2b, int f2b_len, float* f4)
{
    float f;
    unsigned short hf;
    for (int i = 0; i < f2b_len / 2; i++) {
        std::memcpy(&hf, f2b + i * 2, 2);
        f = half_to_float(hf);
        f4[i] = f;
    }
}

void bin16::f4b_to_f2b(unsigned char* float4buf,
                       int float4buf_len,
                       unsigned char* f2b)
{
    float f;
    unsigned short hf;
    for (int i = 0; i < float4buf_len / 4; i++) {
        std::memcpy(&f, float4buf + i * 4, 4);
        hf = float_to_half(f);
        std::memcpy(f2b + i * 2, &hf, 2);
    }
}

float bin16::half_to_float(const unsigned short x)
{ // IEEE-754 16-bit floating-point format (without infinity): 1-5-10,
  // exp-15,
  // +-131008.0, +-6.1035156E-5, +-5.9604645E-8, 3.311 digits
    const unsigned int e = (x & 0x7C00) >> 10; // exponent
    const unsigned int m = (x & 0x03FF) << 13; // mantissa
    const unsigned int v
        = as_uint((float)m) >> 23; // evil log2 bit hack to count leading
                                   // zeros in denormalized format
    return as_float(
        (x & 0x8000) << 16 | (e != 0) * ((e + 112) << 23 | m)
        | ((e == 0) & (m != 0))
              * ((v - 37) << 23
                 | ((m << (150 - v))
                    & 0x007FE000))); // sign : normalized : denormalized
}

unsigned short bin16::float_to_half(const float x)
{ // IEEE-754 16-bit floating-point format (without infinity): 1-5-10,
  // exp-15,
  // +-131008.0, +-6.1035156E-5, +-5.9604645E-8, 3.311 digits
    const unsigned int b
        = as_uint(x) + 0x00001000; // round-to-nearest-even: add last
                                   // bit after truncated mantissa
    const unsigned int e = (b & 0x7F800000) >> 23; // exponent
    const unsigned int m
        = b & 0x007FFFFF; // mantissa; in line below: 0x007FF000 =
                          // 0x00800000-0x00001000 = decimal indicator
                          // flag - initial rounding
    return (b & 0x80000000) >> 16
           | (e > 112) * ((((e - 112) << 10) & 0x7C00) | m >> 13)
           | ((e < 113) & (e > 101))
                 * ((((0x007FF000 + m) >> (125 - e)) + 1) >> 1)
           | (e > 143) * 0x7FFF; // sign : normalized : denormalized : saturate
}

unsigned int bin16::as_uint(const float x)
{
    return *(unsigned int*)&x;
}

float bin16::as_float(const unsigned int x)
{
    return *(float*)&x;
}
