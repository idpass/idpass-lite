
#ifdef __cplusplus

#include <dlib/clustering.h>
#include <dlib/dnn.h>
#include <dlib/image_io.h>
#include <dlib/image_processing/frontal_face_detector.h>
#include <dlib/string.h>
#include <sstream>

#ifndef _WIN32
#ifdef __ANDROID__
#include <android/log.h>

#define LOGI(...) ((void)__android_log_print( \
        ANDROID_LOG_INFO, "dxlog::", __VA_ARGS__))
#else
#define LOGI(...)
#endif
#else
#define LOGI(...)
#endif

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
int load2matrix(char* img, int img_len, dlib::matrix<dlib::rgb_pixel>& image)
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

int computeface128d(char* photo, int photo_len, float* f128d)
{
    // feed photo to Dlib (no file system)
    // pass f128d to Dlib API to fill-in
    // returns the count of faces detected

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
