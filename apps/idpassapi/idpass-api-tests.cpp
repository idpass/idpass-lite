#include "dlib_api.h"
#include "helper.h"
#include "idpass-api.h"
#include "protogen/card_access.pb.h"
#include "sodium.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

class idpass_api_tests : public testing::Test
{
protected:
    time_t start_time_;
    int status;
    int kounter = 0;

    ///////////////////////////////////////////////////////////////////////
    unsigned char encryptionKey[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
    unsigned char signature_pk[crypto_sign_PUBLICKEYBYTES]; // 32
    unsigned char signature_sk[crypto_sign_SECRETKEYBYTES]; // 64
    unsigned char* verificationKeys;
    int vkcount;
    unsigned char* signature_pk_list;
    unsigned char* signature_sk_list;
    void* ctx;
    ////////////

    void SetUp() override
    {
        srand(time(0));
        start_time_ = time(nullptr);
        status = sodium_init();

        vkcount = 0;
        crypto_aead_chacha20poly1305_ietf_keygen(encryptionKey);
        int iret = crypto_sign_keypair(signature_pk, signature_sk);

        int r = rand() % 7 + 1;
        if (r > 0) {
            signature_pk_list
                = new unsigned char[crypto_sign_PUBLICKEYBYTES * r];
            signature_sk_list
                = new unsigned char[crypto_sign_SECRETKEYBYTES * r];

            verificationKeys
                = new unsigned char[crypto_sign_PUBLICKEYBYTES * (r + 0)];

            for (int i = 0; i < r; i++) {
                int iret = crypto_sign_keypair(&signature_pk_list[i],
                                               &signature_sk_list[i]);

                std::memcpy(verificationKeys + crypto_sign_PUBLICKEYBYTES * i,
                            &signature_pk_list[i],
                            crypto_sign_PUBLICKEYBYTES);
            }
            vkcount = r;
        }

        ctx = idpass_api_init(
            encryptionKey, signature_sk, verificationKeys, vkcount);
    }

    void TearDown() override
    {
        // Gets the time when the test finishes
        const time_t end_time = time(nullptr);

        // Asserts that the test took no more than ~5 seconds.  Did you
        // know that you can use assertions in SetUp() and TearDown() as
        // well?
        // EXPECT_TRUE(end_time - start_time_ <= 5) << "The test took too
        // long.";

        delete[] verificationKeys;
        delete[] signature_sk_list;
        delete[] signature_pk_list;

        idpass_api_cleanup(ctx);
    }
};

TEST_F(idpass_api_tests, facemismatch_test)
{
    std::vector<char> img1 = helper::readfile("dat/img1.bmp");
    std::vector<char> img3 = helper::readfile("dat/img3.jpg");

    int nbytes = 2; // value of 2 is default

    unsigned char img1_array[128 * nbytes];
    unsigned char img3_array[128 * nbytes];

    dlib_api::computeface128d(img1.data(), img1.size(), img1_array);
    dlib_api::computeface128d(img3.data(), img3.size(), img3_array);

    std::vector<float> img1_128d = helper::get128f(img1_array,128*nbytes);
    std::vector<float> img3_128d = helper::get128f(img3_array,128*nbytes);

    float img1d[128];
    float img3d[128];

    std::copy(img1_128d.begin(), img1_128d.end(), img1d);
    std::copy(img3_128d.begin(), img3_128d.end(), img3d);

    float result = helper::vectorDistance(img1d, img1d + 128, img3d);

    ASSERT_TRUE(result > 0.6);
}

TEST_F(idpass_api_tests, faceMismatch_test2)
{
    std::vector<char> img1 = helper::readfile("dat/img1.bmp");
    std::vector<char> img3 = helper::readfile("dat/img3.jpg");

    int ecard_len;
    unsigned char* ecard
        = idpass_api_create_card_with_face(ctx,
                                           &ecard_len,
                                           "Pacquiao",
                                           "Manny",
                                           "1978/12/17",
                                           "Philippines",
                                           "sport:boxing,gender:male",
                                           img1.data(),
                                           img1.size(),
                                           "12345");

    int details_len;
    unsigned char* details = idpass_api_verify_card_with_face(
        ctx, &details_len, ecard, ecard_len, img3.data(), img3.size());

    idpass::CardDetails cardDetails;
    cardDetails.ParseFromArray(details, details_len);
    std::cout << cardDetails.surname() << ", " << cardDetails.givenname()
              << std::endl;

    ASSERT_STRNE(cardDetails.surname().c_str(), "Pacquiao");
}

TEST_F(idpass_api_tests, facematch_test3)
{
    std::vector<char> img1 = helper::readfile("dat/img1.bmp");
    std::vector<char> img2 = helper::readfile("dat/img2.bmp");

    int ecard_len;
    unsigned char* ecard
        = idpass_api_create_card_with_face(ctx,
                                           &ecard_len,
                                           "Smith",
                                           "John",
                                           "1978/12/17",
                                           "Cebu",
                                           "sport:boxing,gender:male",
                                           img1.data(),
                                           img1.size(),
                                           "12345");

    const char* data = "this is a test message";

    int signature_len;
    unsigned char* signature = idpass_api_sign_with_card(ctx,
                                                         &signature_len,
                                                         ecard,
                                                         ecard_len,
                                                         (unsigned char*)data,
                                                         std::strlen(data));

    ASSERT_TRUE(signature != nullptr);

    int card_len;
    unsigned char* card = idpass_api_verify_card_with_pin(
        ctx, &card_len, ecard, ecard_len, "12345");
    idpass::CardDetails cardDetails;
    cardDetails.ParseFromArray(card, card_len);
    std::cout << cardDetails.surname() << ", " << cardDetails.givenname()
              << std::endl;

    ASSERT_STREQ(cardDetails.surname().c_str(), "Smith");
    ASSERT_STREQ(cardDetails.givenname().c_str(), "John");
    ASSERT_STREQ(cardDetails.placeofbirth().c_str(), "Cebu");
}

TEST_F(idpass_api_tests, facematch_test)
{
    std::vector<char> img1 = helper::readfile("dat/img1.bmp");
    std::vector<char> img2 = helper::readfile("dat/img2.bmp");

    int ecard_len;
    unsigned char* ecard
        = idpass_api_create_card_with_face(ctx,
                                           &ecard_len,
                                           "Pacquiao",
                                           "Manny",
                                           "1978/12/17",
                                           "Philippines",
                                           "sport:boxing,gender:male",
                                           img1.data(),
                                           img1.size(),
                                           "12345");

    int details_len;
    unsigned char* details = idpass_api_verify_card_with_face(
        ctx, &details_len, ecard, ecard_len, img2.data(), img2.size());

    idpass::CardDetails cardDetails;
    cardDetails.ParseFromArray(details, details_len);
    std::cout << cardDetails.surname() << ", " << cardDetails.givenname()
              << std::endl;

    ASSERT_STREQ(cardDetails.surname().c_str(), "Pacquiao");
    ASSERT_STREQ(cardDetails.givenname().c_str(), "Manny");
    ASSERT_STREQ(cardDetails.placeofbirth().c_str(), "Philippines");
}
