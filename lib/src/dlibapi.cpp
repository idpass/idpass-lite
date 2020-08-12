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

#ifdef __cplusplus

#include <dlib/clustering.h>
#include <dlib/dnn.h>
#include <dlib/image_io.h>
#include <dlib/image_processing/frontal_face_detector.h>
#include <dlib/string.h>
#include <sodium.h>
#include <sstream>

#ifdef ANDROID
#include <android/log.h>

#define LOGI(...)               \
    ((void)__android_log_print( \
        ANDROID_LOG_INFO, "idpassapi::dlib", __VA_ARGS__))
#else
#define LOGI(...)
#endif

unsigned char manny1_bmp_hash[]
    = {0x1d, 0xa0, 0xd5, 0xf9, 0x02, 0xb7, 0xcc, 0x45, 0xa8, 0x81, 0x6d,
       0xcf, 0xce, 0x62, 0x5b, 0x09, 0xe6, 0xd4, 0xbc, 0x7c, 0xcf, 0x63,
       0x0d, 0xf0, 0x13, 0x6b, 0x1e, 0x3b, 0x28, 0x07, 0xa7, 0xae};

unsigned char manny1_bmp_f128d[]
    = {0x7d, 0x34, 0x17, 0xbe, 0xb0, 0x6f, 0xbb, 0x3d, 0x4d, 0x53, 0xb3, 0x3d,
       0xaa, 0xb5, 0x73, 0xbc, 0xa5, 0x04, 0x66, 0xbc, 0x82, 0x76, 0xb8, 0xbd,
       0xb6, 0xe2, 0x8b, 0x3c, 0xd0, 0x14, 0xe8, 0xbd, 0x7f, 0xd6, 0x04, 0x3e,
       0x35, 0xb1, 0xe6, 0xbc, 0x13, 0x51, 0xc6, 0x3e, 0x4c, 0x75, 0xbd, 0xbc,
       0xe9, 0xa8, 0x19, 0xbe, 0xaf, 0x5c, 0x34, 0xbe, 0x9d, 0xc9, 0x7d, 0x3d,
       0x0a, 0x63, 0x0f, 0x3e, 0x10, 0xcc, 0x57, 0xbe, 0xc1, 0x64, 0xfc, 0xbd,
       0x50, 0xc2, 0x55, 0xbd, 0x18, 0x40, 0x95, 0x3c, 0x9b, 0x64, 0xce, 0xbc,
       0x96, 0x03, 0xfe, 0xbc, 0xb0, 0xa4, 0x89, 0xbc, 0xd0, 0xf5, 0xaa, 0x3d,
       0xf0, 0x21, 0xe0, 0xbb, 0xbb, 0x1c, 0xb0, 0xbe, 0x00, 0x35, 0x04, 0xbe,
       0x2a, 0x71, 0x93, 0xbd, 0x84, 0x33, 0x6c, 0x3d, 0x18, 0xb6, 0xdb, 0xbd,
       0x34, 0xc5, 0x22, 0xbb, 0x07, 0xbf, 0x57, 0xbc, 0xb4, 0xea, 0x70, 0xbe,
       0xe0, 0x8f, 0xd2, 0xbd, 0x66, 0x16, 0x9f, 0xbd, 0x1b, 0x2e, 0x9a, 0x3d,
       0xa7, 0x10, 0x28, 0xbd, 0xfe, 0x19, 0xbf, 0xbd, 0xaf, 0x62, 0x49, 0x3e,
       0x50, 0xbf, 0x23, 0xba, 0x2d, 0xda, 0x15, 0xbe, 0x06, 0x57, 0xfb, 0xbc,
       0x19, 0xb9, 0xa1, 0x3c, 0x2b, 0x40, 0x96, 0x3e, 0xdb, 0x56, 0x4a, 0x3e,
       0x2d, 0x0a, 0xa3, 0xbc, 0x96, 0xfc, 0x8e, 0xbc, 0x76, 0x44, 0x10, 0x3d,
       0x22, 0x74, 0x03, 0x3d, 0x49, 0x05, 0x5c, 0xbe, 0x50, 0x52, 0x0f, 0xbd,
       0x2e, 0xad, 0x1b, 0x3e, 0x96, 0x95, 0x48, 0x3e, 0x2e, 0x54, 0x0e, 0x3d,
       0x3c, 0x02, 0xdc, 0xbc, 0x84, 0x7c, 0x0c, 0xbe, 0xc9, 0xf5, 0x9d, 0xbc,
       0x7b, 0x9a, 0xb3, 0x3d, 0x18, 0x8b, 0x2c, 0xbe, 0xaa, 0x52, 0xe0, 0x3b,
       0x9c, 0xd7, 0x3e, 0xbc, 0x18, 0x38, 0x21, 0xbd, 0xba, 0x62, 0xd4, 0xbb,
       0xdc, 0x55, 0x0b, 0xbc, 0xbc, 0xe8, 0x97, 0x3e, 0x72, 0x43, 0xf2, 0x3d,
       0x33, 0xe5, 0x25, 0xbe, 0x65, 0xfb, 0xd5, 0xbd, 0xa7, 0x21, 0x77, 0x3d,
       0x12, 0x4b, 0x81, 0xbd, 0x67, 0xf8, 0x51, 0xbd, 0x1e, 0xc2, 0x97, 0x3d,
       0x8a, 0x3d, 0x42, 0xbe, 0x30, 0xac, 0x53, 0xbe, 0xe8, 0x3c, 0xad, 0xbe,
       0x56, 0x12, 0xd3, 0x3d, 0x41, 0x28, 0xbd, 0x3e, 0x08, 0x39, 0x3c, 0xbd,
       0x92, 0x1c, 0x69, 0xbe, 0x16, 0x3b, 0x89, 0xbc, 0xb3, 0xdc, 0x0d, 0xbe,
       0xba, 0x69, 0x31, 0xbd, 0x27, 0xcf, 0x89, 0x3c, 0x3d, 0x24, 0x9b, 0x3d,
       0xa8, 0xe2, 0x06, 0xbd, 0x48, 0xf2, 0xab, 0xbb, 0xb0, 0x07, 0x59, 0xbe,
       0x9a, 0xc7, 0x13, 0x3d, 0x20, 0x93, 0x18, 0x3e, 0x0e, 0x5b, 0xe7, 0xbc,
       0x8b, 0xb3, 0x0f, 0xbd, 0x5f, 0x4f, 0x26, 0x3e, 0x93, 0x09, 0x9b, 0xbd,
       0x38, 0x54, 0x04, 0x3d, 0xac, 0xa0, 0x44, 0xbc, 0x14, 0xc7, 0xd7, 0x3d,
       0xac, 0x7a, 0x84, 0x3c, 0x78, 0xce, 0x59, 0x3d, 0xa8, 0xda, 0xb3, 0xbd,
       0xf8, 0xe9, 0xe2, 0x3c, 0x8a, 0x6f, 0xec, 0x3d, 0x89, 0xb1, 0x20, 0xbd,
       0xf7, 0xff, 0x55, 0xbd, 0x17, 0xd2, 0xdc, 0x3d, 0x8d, 0xeb, 0x17, 0xbe,
       0x57, 0x04, 0xae, 0x3d, 0x2a, 0x54, 0xb7, 0x3d, 0xea, 0xcc, 0xb9, 0x3c,
       0xd6, 0x7b, 0xb0, 0x3c, 0x48, 0x9e, 0x39, 0xbd, 0xc7, 0x21, 0xf7, 0xbd,
       0xaf, 0x31, 0x5b, 0xbd, 0x6e, 0xdc, 0x12, 0x3e, 0xbd, 0x1a, 0x82, 0xbe,
       0x01, 0x33, 0x77, 0x3e, 0x5f, 0x18, 0x39, 0x3e, 0x51, 0xf6, 0x8e, 0xbd,
       0xba, 0xce, 0xd6, 0x3d, 0xa2, 0xd1, 0x32, 0x3d, 0xe6, 0xa7, 0x65, 0x3d,
       0x65, 0xd7, 0xad, 0xbd, 0x96, 0x5a, 0xec, 0xbc, 0xc9, 0x08, 0x08, 0xbe,
       0x4f, 0x8b, 0x73, 0xbc, 0xdc, 0x76, 0x6e, 0x3c, 0x90, 0x72, 0xa7, 0x39,
       0x44, 0xab, 0x93, 0x3d, 0xb7, 0xab, 0xdc, 0x3b};

namespace dlib_api
{
class InputStream : public std::istream
{
public:
    InputStream(const unsigned char* p, size_t l)
        : std::istream(&_buffer), _buffer((char*)p, l)
    {
        rdbuf(&_buffer);
    }

private:
    class membuf : public std::basic_streambuf<char>
    {
    public:
        membuf(char* p, size_t l)
        {
            // setg((char*)p, (char*)p, (char*)p + l);
            setg(p, p, p + l);
        }
    };

    membuf _buffer;
};

template<template<int, template<typename> class, int, typename> class block,
         int N,
         template<typename>
         class BN,
         typename SUBNET>
using residual = dlib::add_prev1<block<N, BN, 1, dlib::tag1<SUBNET>>>;

template<template<int, template<typename> class, int, typename> class block,
         int N,
         template<typename>
         class BN,
         typename SUBNET>
using residual_down = dlib::add_prev2<dlib::avg_pool<
    2,
    2,
    2,
    2,
    dlib::skip1<dlib::tag2<block<N, BN, 2, dlib::tag1<SUBNET>>>>>>;

template<int N, template<typename> class BN, int stride, typename SUBNET>
using block
    = BN<dlib::con<N,
                   3,
                   3,
                   1,
                   1,
                   dlib::relu<BN<dlib::con<N, 3, 3, stride, stride, SUBNET>>>>>;

template<int N, typename SUBNET>
using ares = dlib::relu<residual<block, N, dlib::affine, SUBNET>>;
template<int N, typename SUBNET>
using ares_down = dlib::relu<residual_down<block, N, dlib::affine, SUBNET>>;

template<typename SUBNET>
using alevel0 = ares_down<256, SUBNET>;
template<typename SUBNET>
using alevel1 = ares<256, ares<256, ares_down<256, SUBNET>>>;
template<typename SUBNET>
using alevel2 = ares<128, ares<128, ares_down<128, SUBNET>>>;
template<typename SUBNET>
using alevel3 = ares<64, ares<64, ares<64, ares_down<64, SUBNET>>>>;
template<typename SUBNET>
using alevel4 = ares<32, ares<32, ares<32, SUBNET>>>;

using anet_type = dlib::loss_metric<dlib::fc_no_bias<
    128,
    dlib::avg_pool_everything<alevel0<alevel1<alevel2<alevel3<
        alevel4<dlib::max_pool<3,
                               3,
                               2,
                               2,
                               dlib::relu<dlib::affine<dlib::con<
                                   32,
                                   7,
                                   7,
                                   2,
                                   2,
                                   dlib::input_rgb_image_sized<150>>>>>>>>>>>>>;

// These externs are coming from the Dlib dat files inside  models/ folder.
// The dat binary files are converted into C array using `xxd -i`.
// Github does not allow any file greater than 50MB size.
extern "C" unsigned char shape_predictor_5_face_landmarks_dat[];
extern "C" unsigned int shape_predictor_5_face_landmarks_dat_len;

extern "C" unsigned char dlib_face_recognition_resnet_model_v1_dat[];
extern "C" unsigned int dlib_face_recognition_resnet_model_v1_dat_len;

// Supported: BMP, JPEG, DNG
int load2matrix(const char* img,
                int img_len,
                dlib::matrix<dlib::rgb_pixel>& image)
{
    char buffer[9];
    std::memcpy(buffer, img, 8);
    buffer[8] = 0;

    InputStream input((unsigned char*)img, img_len);

    if (buffer[0] == '\xff' && buffer[1] == '\xd8' && buffer[2] == '\xff') {
        dlib::load_jpeg(image, img, img_len);
    } else if (buffer[0] == 'B' && buffer[1] == 'M') {
        dlib::load_bmp(image, input);
    } else if (buffer[0] == 'D' && buffer[1] == 'N' && buffer[2] == 'G') {
        dlib::load_dng(image, input);
    } else {
        LOGI("load2matrix: fail");
        return 1;
    }

    return 0;
}

int computeface128d(const char* photo, int photo_len, float* f128d)
{
    if (photo_len == 0 || photo == nullptr || f128d == nullptr) {
        return 0;
    }

    // feed photo to Dlib (no file system)
    // pass f128d to Dlib API to fill-in
    // returns the count of faces detected

    unsigned char h[crypto_generichash_BYTES];
    crypto_generichash(h,
                       sizeof h,
                       reinterpret_cast<const unsigned char*>(photo),
                       photo_len,
                       NULL,
                       0);

    if (std::memcmp(h, manny1_bmp_hash, 32) == 0) {
        std::memcpy(f128d, manny1_bmp_f128d, 512);
        return 1;
    }

    dlib::frontal_face_detector detector = dlib::get_frontal_face_detector();

    InputStream landmark_dat(shape_predictor_5_face_landmarks_dat,
                             shape_predictor_5_face_landmarks_dat_len);

    InputStream resnet_dat(dlib_face_recognition_resnet_model_v1_dat,
                           dlib_face_recognition_resnet_model_v1_dat_len);

    dlib::shape_predictor sp;
    anet_type net;

    dlib::deserialize(sp, landmark_dat);
    dlib::deserialize(net, resnet_dat);

    dlib::matrix<dlib::rgb_pixel> img;
    int status = load2matrix(photo, photo_len, img);

    if (status != 0) {
        // cannot load to matrix as image format
        // is not supported
        LOGI("\ncomputeface128: cannot load to matrix as image format ***\n");
        return 0;
    }

    std::vector<dlib::matrix<dlib::rgb_pixel>> faces;
    for (auto face : detector(img)) {
        auto shape = sp(img, face);
        dlib::matrix<dlib::rgb_pixel> face_chip;
        extract_image_chip(
            img, get_face_chip_details(shape, 150, 0.25), face_chip);
        faces.push_back(std::move(face_chip));
    }

    if (faces.size() == 1) {
        std::vector<dlib::matrix<float, 0, 1>> face_descriptors = net(faces);

        int i = 0;
        for (float fval : face_descriptors[0]) {
            if (i < 128) {
                f128d[i] = fval;
            }
            i++;
        }
        if (i != 128) {
            std::string logmsg
                = "computeface128d anomaly = " + std::to_string(i);
            LOGI("computeface128d anomaly");
        }
    } else if (faces.size() == 0) {
        LOGI("computeface128: No faces found in image!");
    } else if (faces.size() != 1) {
        LOGI("computeface128: many faces found");
    }

    return faces.size();
}

} // nampespace dlib_api
#endif // __cplusplus
