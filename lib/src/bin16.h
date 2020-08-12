/*
 * Copyright (C) 2020 Newlogic Impact Lab Pte. Ltd.
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

class bin16
{
public:
    static void f4_to_f4b(float* f4, int f4_len, unsigned char* f4b);
    static void f4_to_f2b(float* f4, int f4_len, unsigned char* f2b);
    static void f4_to_f2(float* f4, int f4_len, float* f2);
    static void
    f4b_to_f2(unsigned char* float4buf, int float4buf_len, float* f2);
    static void
    f4b_to_f4(unsigned char* float4buf, int float4buf_len, float* f4);
    static void
    f2b_to_f2(unsigned char* float2buf, int float2buf_len, float* f2);
    static void f2b_to_f4(unsigned char* f2b, int f2b_len, float* f4);
    static void
    f4b_to_f2b(unsigned char* float4buf, int float4buf_len, unsigned char* f2b);
    static float half_to_float(const unsigned short x);
    static unsigned short float_to_half(const float x);

private:
    static unsigned int as_uint(const float x);
    static float as_float(const unsigned int x);
};
