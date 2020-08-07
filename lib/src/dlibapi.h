#ifdef __cplusplus
#include <dlib/image_io.h>
#include <vector>

namespace dlib_api
{
int computeface128d(const char* photo, int photo_len, float* f128d);
int load2matrix(const char* img,
                int img_len,
                dlib::matrix<dlib::rgb_pixel>& image);
}

#endif
