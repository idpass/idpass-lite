#ifdef __cplusplus
#include <dlib/image_io.h>
#include <vector>

namespace dlib_api
{
int computeface128d(char* photo, int photo_len, float* f128d);
int load2matrix(char* img, int img_len, dlib::matrix<dlib::rgb_pixel>& image);
}

#endif
