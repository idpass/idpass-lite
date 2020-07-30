#include "idpass.h"
#include "proto/card_access/card_access.pb.h"
#include "sodium.h"

#include "Cert.h"

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

#ifdef _WIN32
  // https://stackoverflow.com/questions/11238918/s-isreg-macro-undefined
  #define _CRT_INTERNAL_NONSTDC_NAMES 1
  #include <sys/stat.h>

  #if !defined(S_ISREG) && defined(S_IFMT) && defined(S_IFREG)
    #define S_ISREG(m) (((m)&S_IFMT) == S_IFREG)
  #endif

  #if !defined(S_ISDIR) && defined(S_IFMT) && defined(S_IFDIR)
    #define S_ISDIR(m) (((m)&S_IFMT) == S_IFDIR)
  #endif
#endif

char const* datapath = "data/";

unsigned char encryptionKey[] = {
  0xf8, 0x0b, 0x95, 0x79, 0x69, 0xd1, 0xe8, 0x60, 
  0x6c, 0x33, 0x56, 0x00, 0x76, 0x31, 0xe9, 0x2d, 
  0x14, 0x79, 0x9d, 0x65, 0x1f, 0x35, 0x0f, 0x89,
  0x87, 0x7c, 0x05, 0xa0, 0x3e, 0xc5, 0xaa, 0x3e
}; // 32

unsigned char signature_sk[] = {
  0x2d, 0x52, 0xf8, 0x6a, 0xaa, 0x4d, 0x62, 0xfc, 
  0xab, 0x4d, 0xb0, 0x0a, 0x21, 0x1a, 0x12, 0x60, 
  0xf8, 0x17, 0xc5, 0xf2, 0xba, 0xb7, 0x3e, 0xfe,
  0xd6, 0x36, 0x07, 0xbc, 0x9d, 0xb3, 0x96, 0xee, 
  0x57, 0xc6, 0x33, 0x09, 0xfa, 0xc2, 0x1b, 0x60, 
  0x04, 0x76, 0x4e, 0xf6, 0xf7, 0xc6, 0x2f, 0x28,
  0xcf, 0x63, 0x40, 0xbe, 0x13, 0x10, 0x6e, 0x80, 
  0xed, 0x70, 0x41, 0x8f, 0xa1, 0xb9, 0x27, 0xb4
}; // 64

unsigned char verification_pk[] = {
  0x57, 0xc6, 0x33, 0x09, 0xfa, 0xc2, 0x1b, 0x60, 
  0x04, 0x76, 0x4e, 0xf6, 0xf7, 0xc6, 0x2f, 0x28,
  0xcf, 0x63, 0x40, 0xbe, 0x13, 0x10, 0x6e, 0x80, 
  0xed, 0x70, 0x41, 0x8f, 0xa1, 0xb9, 0x27, 0xb4
}; // 32

// A single instance of idpass_api_init context
// called in multiple threads
void single_instance_test(void* ctx)
{
    std::string inputfile = std::string(datapath) + "manny1.bmp";
    std::ifstream f1(inputfile, std::ios::binary);
    ASSERT_TRUE(f1.is_open());

    idpass::Dictionary pub_extras;
    idpass::Dictionary priv_extras;

    idpass::Pair *kv = pub_extras.add_pairs();
    kv->set_key("gender");
    kv->set_value("male");

    kv = priv_extras.add_pairs();
    kv->set_key("address");
    kv->set_value("16th Elm Street");

    std::vector<unsigned char> pubExtras(pub_extras.ByteSizeLong());
    std::vector<unsigned char> privExtras(priv_extras.ByteSizeLong());

    pub_extras.SerializeToArray(pubExtras.data(), pubExtras.size());
    priv_extras.SerializeToArray(privExtras.data(), privExtras.size());

    std::vector<char> photo(std::istreambuf_iterator<char>{f1}, {});

    unsigned char ioctlcmd[] = {
        IOCTL_SET_ACL, 
        ACL_PLACEOFBIRTH | ACL_GIVENNAME}; // make givenname, placeofbirth visible

    idpass_api_ioctl(ctx, nullptr, ioctlcmd, sizeof ioctlcmd);

    idpass::Date dob;
    dob.set_year(1980);
    dob.set_month(12);
    dob.set_day(17);
    int len = dob.ByteSizeLong();
    std::vector<unsigned char> dob_buf(len);
    dob.SerializeToArray(dob_buf.data(), len);

    int card_len;
    unsigned char* card = idpass_api_create_card_with_face(ctx,
                                                           &card_len,
                                                           "Doe",
                                                           "John",
                                                           dob_buf.data(),
                                                           dob_buf.size(),
                                                           "USA",
                                                           "12345",
                                                           photo.data(),
                                                           photo.size(),
                                                           pubExtras.data(),
                                                           pubExtras.size(),
                                                           privExtras.data(),
                                                           privExtras.size());

    idpass::IDPassCards cards;
    cards.ParseFromArray(card, card_len);

    ASSERT_TRUE(cards.publiccard().details().surname().empty());
    //std::cout << cards.publiccard().details().surname();

    ASSERT_TRUE(
        !cards.publiccard().details().givenname().empty() && 
        cards.publiccard().details().givenname().compare("John") == 0);

    ASSERT_TRUE(cards.publiccard().details().dateofbirth().ByteSizeLong() == 0);

    ASSERT_TRUE(
        !cards.publiccard().details().placeofbirth().empty() && 
        cards.publiccard().details().placeofbirth().compare("USA") == 0);

    unsigned char* ecard = (unsigned char*)cards.encryptedcard().data();
    int ecard_len = cards.encryptedcard().size();

    int buf_len;
    unsigned char* buf = idpass_api_verify_card_with_face(
        ctx, &buf_len, card, card_len, photo.data(), photo.size());

    ASSERT_TRUE(buf != nullptr);

    if (buf) {
        idpass::CardDetails details;
        bool flag = details.ParseFromArray(buf, buf_len);
        ASSERT_TRUE(flag);
        if (flag) {
            //std::cout << details.surname() << std::flush;
        }
    }
}

// Multiple different instances of idpass_api_init contexts
// called in multiple threads per contexts
void multiple_instance_test()
{
    unsigned char enc[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
    unsigned char sig_skpk[crypto_sign_SECRETKEYBYTES];
    unsigned char sig_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char verif_pk[crypto_sign_PUBLICKEYBYTES];

    crypto_aead_chacha20poly1305_keygen(enc);
    crypto_sign_keypair(sig_pk, sig_skpk);
    std::memcpy(verif_pk, sig_pk, crypto_sign_PUBLICKEYBYTES);

    void* context = idpass_api_init(enc,
                               crypto_aead_chacha20poly1305_IETF_KEYBYTES,
                               sig_skpk,
                               crypto_sign_SECRETKEYBYTES,
                               verif_pk,
                               crypto_sign_PUBLICKEYBYTES,nullptr,nullptr,0);
   // printf("context = %p\n", context);
    std::string inputfile = std::string(datapath) + "manny1.bmp"; 
    std::ifstream f1(inputfile, std::ios::binary);
    ASSERT_TRUE(f1.is_open());

    idpass::Dictionary pub_extras;
    idpass::Dictionary priv_extras;

    idpass::Pair *kv = pub_extras.add_pairs();
    kv->set_key("gender");
    kv->set_value("male");

    kv = priv_extras.add_pairs();
    kv->set_key("address");
    kv->set_value("16th Elm Street");

    std::vector<unsigned char> pubExtras(pub_extras.ByteSizeLong());
    std::vector<unsigned char> privExtras(priv_extras.ByteSizeLong());

    pub_extras.SerializeToArray(pubExtras.data(), pubExtras.size());
    priv_extras.SerializeToArray(privExtras.data(), privExtras.size());

    idpass::Date dob;
    dob.set_year(1980);
    dob.set_month(12);
    dob.set_day(17);
    int len = dob.ByteSizeLong();
    std::vector<unsigned char> dob_buf(len);
    dob.SerializeToArray(dob_buf.data(), len);

    std::vector<char> photo(std::istreambuf_iterator<char>{f1}, {});
    int card_len;
    unsigned char* card = idpass_api_create_card_with_face(context,
                                                           &card_len,
                                                           "Doe",
                                                           "John",
                                                           dob_buf.data(), //"1980/12/25",
                                                           dob_buf.size(),
                                                           "USA",
                                                           "12345",
                                                           photo.data(),
                                                           photo.size(),
                                                           pubExtras.data(),
                                                           pubExtras.size(),
                                                           privExtras.data(),
                                                           privExtras.size());

    idpass::IDPassCards cards;
    cards.ParseFromArray(card, card_len);
    //std::cout << cards.publiccard().details().surname();

    unsigned char* ecard = (unsigned char*)cards.encryptedcard().data();
    int ecard_len = cards.encryptedcard().size();

    int buf_len;
    unsigned char* buf = idpass_api_verify_card_with_face(
        context, &buf_len, card, card_len, photo.data(), photo.size());

    ASSERT_TRUE(buf != nullptr);

    if (buf) {
        idpass::CardDetails details;
        bool flag = details.ParseFromArray(buf, buf_len);
        ASSERT_TRUE(flag);
        if (flag) {
            //std::cout << details.surname() << std::flush;
        }
    }
}

void savetobitmap(int qrcode_size, unsigned char* pixelbits,
    const char* outfile = "/tmp/qrcode.bmp")
{
    auto TestBit = [](unsigned char A[], int k) {
        return ((A[k / 8] & (1 << (k % 8))) != 0);
    };

    int width = qrcode_size;
    int height = qrcode_size;

    int size = width * height * 4;
    char header[54] = {0};
    strcpy(header, "BM");
    memset(&header[2], (int)(54 + size), 1);
    memset(&header[10], (int)54, 1); // always 54
    memset(&header[14], (int)40, 1); // always 40
    memset(&header[18], (int)width, 1);
    memset(&header[22], (int)height, 1);
    memset(&header[26], (short)1, 1);
    memset(&header[28], (short)32, 1); // 32bit
    memset(&header[34], (int)size, 1); // pixel size

    unsigned char* pixelbytes = new unsigned char[width * height * 4];
    std::memset(pixelbytes, 0x00, width * height * 4);
    int q = 0;

    for (uint8_t y = 0; y < width; y++) {
        // Each horizontal module
        for (uint8_t x = 0; x < height; x++) {
            int p = (y * height + x) * 4;

            if (TestBit(pixelbits, q++)) {
                pixelbytes[p + 0] = 255;
                pixelbytes[p + 1] = 0;
                pixelbytes[p + 2] = 0;
            } else {
                pixelbytes[p + 0] = 255;
                pixelbytes[p + 1] = 255;
                pixelbytes[p + 2] = 255;
            }
        }
    }

    FILE* fout = fopen(outfile, "wb");
    fwrite(header, 1, 54, fout);
    fwrite(pixelbytes, 1, size, fout);

    delete[] pixelbytes;
    fclose(fout);
}

class idpass_api_tests : public testing::Test
{
protected:
    time_t start_time_;
    int status;
    void* ctx;
    Cert* pROOTCA;
    std::vector<unsigned char> dob_buf;

    void SetUp() override
    {
        srand(time(0));
        start_time_ = time(nullptr);
        status = sodium_init();

        if (status < 0) {
            std::cout << "sodium_init failed";
        }

        idpass::Date dob;
        dob.set_year(1980);
        dob.set_month(12);
        dob.set_day(17);
        int len = dob.ByteSizeLong();
        dob_buf.resize(len);
        dob.SerializeToArray(dob_buf.data(), len);

        pROOTCA = new Cert(); // self-signed Cert

        int count = 1;
        unsigned char** cert = nullptr;
        int* nlen = nullptr;
        cert = new unsigned char*[count];
        nlen = new int[count];
        nlen[0] = pROOTCA->toByteArray(true).size(); // 160
        cert[0] = new unsigned char[pROOTCA->toByteArray(true).size()];
        std::memcpy(cert[0], pROOTCA->toByteArray(true).data(), pROOTCA->toByteArray(true).size());

        ctx = idpass_api_init(
            encryptionKey, 
            crypto_aead_chacha20poly1305_IETF_KEYBYTES, 
            signature_sk, 
            crypto_sign_SECRETKEYBYTES,
            verification_pk,
            crypto_sign_PUBLICKEYBYTES, cert, nlen, count);

        delete[] cert[0];
        delete[] cert;
        delete[] nlen;
    }

    void TearDown() override
    {
        // Gets the time when the test finishes
        const time_t end_time = time(nullptr);
        idpass_api_freemem(ctx, ctx);
        delete pROOTCA;
    }


};

TEST_F(idpass_api_tests, basic_initialization)
{
    ASSERT_TRUE(ctx != nullptr);
}

TEST_F(idpass_api_tests, chain_of_trust_test2)
{
    auto verify_chain = [this](std::vector<Cert>& chain, bool expected) {
        int count = chain.size();
        unsigned char** cert = new unsigned char*[count];
        std::memset(cert, 0x00, count * sizeof(unsigned char*));
        int* nlen = new int[count];
        int j = 0;

        for (auto& c : chain) {
            std::vector<unsigned char> buffe = c.toByteArray();
            nlen[j] = buffe.size();
            cert[j] = new unsigned char[buffe.size()];
            std::memcpy(cert[j], buffe.data(), buffe.size());
            j++;
        }

        int status;
        status = idpass_api_add_certificates(ctx, cert, nlen, count);

        for (int i = 0; i < count; i++) {
            if (cert[i]) {
                delete[] cert[i];
            }
        }
        delete[] cert;
        delete[] nlen;

        return status == expected ? 0 : 1;
    };

    Cert cert2_rootca;
    Cert cert7_cert2(signature_sk);

    pROOTCA->Sign(cert2_rootca);
    cert2_rootca.Sign(cert7_cert2);

    std::vector<Cert> chain2_valid{cert2_rootca, cert7_cert2};
    ASSERT_TRUE(verify_chain(chain2_valid, true));

    Cert c01_c03; // self-signed during creation
    Cert c02_c01;
    Cert c03_c02;
    c01_c03.Sign(c02_c01);
    c02_c01.Sign(c03_c02);
    c03_c02.Sign(c01_c03); // make it circular

    std::vector<Cert> chain_invalid_circular{ c01_c03, c02_c01, c03_c02 };
    ASSERT_TRUE(verify_chain(chain_invalid_circular, false));

    Cert gamma;
    Cert cert8_gamma;
    gamma.Sign(cert8_gamma);
 
    std::vector<Cert> chain12_valid{gamma, cert8_gamma};
    ASSERT_TRUE(verify_chain(chain12_valid, false));

    pROOTCA->Sign(gamma);
    std::vector<Cert> chain_valid{gamma, cert8_gamma};
    ASSERT_TRUE(verify_chain(chain_valid, true));

    Cert cert001(signature_sk);
    pROOTCA->Sign(cert001);
    std::vector<Cert> chain_1{cert001};
    ASSERT_TRUE(verify_chain(chain_1, true));

    Cert cert002(signature_sk);
    std::vector<Cert> chain_2{cert002};
    ASSERT_TRUE(verify_chain(chain_2, false));
}

TEST_F(idpass_api_tests, create_card_with_certificates)
{
    Cert certifi(signature_sk);

    ASSERT_TRUE(certifi.isRootCA());
    ASSERT_TRUE(certifi.hasValidSignature());

    pROOTCA->Sign(certifi);

    ASSERT_TRUE(certifi.hasValidSignature());
    ASSERT_FALSE(certifi.isRootCA());

    int count = 1;
    unsigned char** cert = nullptr;
    int* nlen = nullptr;
    cert = new unsigned char*[count];
    nlen = new int[count];
    nlen[0] = 128;
    cert[0] = new unsigned char[128];
    std::memcpy(cert[0], certifi.toByteArray().data(), certifi.toByteArray().size());

    ASSERT_TRUE(idpass_api_add_certificates(ctx, cert, nlen, count) == 0);

    std::string inputfile = std::string(datapath) + "manny1.bmp";
    std::ifstream f1(inputfile, std::ios::binary);
    std::vector<char> img1(std::istreambuf_iterator<char>{f1}, {});

    idpass::Dictionary pub_extras;
    idpass::Dictionary priv_extras;

    idpass::Pair *kv = pub_extras.add_pairs();
    kv->set_key("gender");
    kv->set_value("male");

    kv = priv_extras.add_pairs();
    kv->set_key("color");
    kv->set_value("brown");

    std::vector<unsigned char> pubExtras(pub_extras.ByteSizeLong());
    std::vector<unsigned char> privExtras(priv_extras.ByteSizeLong());

    pub_extras.SerializeToArray(pubExtras.data(), pubExtras.size());
    priv_extras.SerializeToArray(privExtras.data(), privExtras.size());

    // transfer givenname, placeofbirth to public region
    // thus, these fields will no longer be in the private region
    // this is to avoid redundancy 
    unsigned char ioctlcmd[] = { IOCTL_SET_ACL, 
        ACL_PLACEOFBIRTH | ACL_GIVENNAME }; 
    idpass_api_ioctl(ctx, nullptr, ioctlcmd, sizeof ioctlcmd);

    int ecard_len;
    unsigned char* ecard = idpass_api_create_card_with_face(
		ctx,
        &ecard_len,
        "Pacquiao",
        "Manny",
        dob_buf.data(), //"1980/12/25",
        dob_buf.size(),
        "Kibawe, Bukidnon",
        "12345",
        img1.data(),
        img1.size(),
        pubExtras.data(),
        pubExtras.size(),
        privExtras.data(),
        privExtras.size());

    ASSERT_TRUE(ecard != nullptr);

    idpass::IDPassCards cards;
    ASSERT_TRUE(cards.ParseFromArray(ecard, ecard_len));

    idpass::Certificate certi;
    for (auto& c : cards.certificates()) {
        std::cout << ".";
    }

    int details_len = 0;
    unsigned char* details = idpass_api_verify_card_with_pin(
        ctx, &details_len, ecard, ecard_len, "12345");

    ASSERT_TRUE(details != nullptr);

    delete[] cert[0];
    delete[] cert;
    delete[] nlen;
}

TEST_F(idpass_api_tests, check_qrcode_md5sum)
{
    std::string inputfile = std::string(datapath) + "manny1.bmp";
    std::ifstream f1(inputfile, std::ios::binary);
    std::vector<char> img1(std::istreambuf_iterator<char>{f1}, {});

    idpass::Dictionary pub_extras;
    idpass::Dictionary priv_extras;

    idpass::Pair *kv = pub_extras.add_pairs();
    kv->set_key("gender");
    kv->set_value("male");

    kv = priv_extras.add_pairs();
    kv->set_key("address");
    kv->set_value("16th Elm Street");

    std::vector<unsigned char> pubExtras(pub_extras.ByteSizeLong());
    std::vector<unsigned char> privExtras(priv_extras.ByteSizeLong());

    pub_extras.SerializeToArray(pubExtras.data(), pubExtras.size());
    priv_extras.SerializeToArray(privExtras.data(), privExtras.size());

    int eSignedIDPassCard_len;
    unsigned char* eSignedIDPassCard = idpass_api_create_card_with_face(
		ctx,
        &eSignedIDPassCard_len,
        "Pacquiao",
        "Manny",
        dob_buf.data(), //"1980/12/25",
        dob_buf.size(),
        "Kibawe, Bukidnon",
        "12345",
        img1.data(),
        img1.size(),
        pubExtras.data(),
        pubExtras.size(),
        privExtras.data(),
        privExtras.size());

    if (eSignedIDPassCard != nullptr) {

        int qrsize = 0;
        unsigned char* pixel = idpass_api_qrpixel(
            ctx,
            eSignedIDPassCard,
            eSignedIDPassCard_len,
            &qrsize);
#ifdef _WIN32
        FILE *fp = fopen("c:/Users/63927/Documents/qrcode.dat", "wb");
#else
        FILE *fp = fopen("/tmp/qrcode.dat", "wb");
#endif
        int nwritten = 0;
        nwritten = fwrite(eSignedIDPassCard , 1, eSignedIDPassCard_len, fp);
        while (nwritten < eSignedIDPassCard_len) {
            nwritten += fwrite(eSignedIDPassCard , 1, eSignedIDPassCard_len + nwritten, fp);
        }
        fclose(fp);
#ifdef _WIN32
        savetobitmap(qrsize, pixel, "c:/Users/63927/Documents/qrcode.bmp");
#else
        savetobitmap(qrsize, pixel, "qrcode.bmp");
#endif
    }
}

TEST_F(idpass_api_tests, createcard_manny_verify_as_brad)
{
    std::string inputfile = std::string(datapath) + "manny1.bmp";
    std::ifstream f1(inputfile, std::ios::binary);
    std::vector<char> img1(std::istreambuf_iterator<char>{f1}, {});

    std::string inputfile2 = std::string(datapath) + "brad.jpg";
    std::ifstream f2(inputfile2, std::ios::binary);
    std::vector<char> img3(std::istreambuf_iterator<char>{f2}, {});

    idpass::Dictionary pub_extras;
    idpass::Dictionary priv_extras;

    idpass::Pair *kv = pub_extras.add_pairs();
    kv->set_key("gender");
    kv->set_value("male");

    kv = priv_extras.add_pairs();
    kv->set_key("address");
    kv->set_value("16th Elm Street");

    std::vector<unsigned char> pubExtras(pub_extras.ByteSizeLong());
    std::vector<unsigned char> privExtras(priv_extras.ByteSizeLong());

    pub_extras.SerializeToArray(pubExtras.data(), pubExtras.size());
    priv_extras.SerializeToArray(privExtras.data(), privExtras.size());

    int ecard_len;
    unsigned char* ecard = idpass_api_create_card_with_face(
        ctx,
        &ecard_len,
        "Pacquiao",
        "Manny",
        dob_buf.data(), //"1980/12/25",
        dob_buf.size(),
        "Kibawe, Bukidnon",
        "12345",
        img1.data(),
        img1.size(),
        pubExtras.data(),
        pubExtras.size(),
        privExtras.data(),
        privExtras.size());

    int details_len;
    unsigned char* details = idpass_api_verify_card_with_face(
        ctx, 
        &details_len, 
        ecard, 
        ecard_len, 
        img3.data(), 
        img3.size()
        );

    idpass::CardDetails cardDetails;
    cardDetails.ParseFromArray(details, details_len);
    //std::cout << cardDetails.surname() << ", " << cardDetails.givenname() << std::endl;

    ASSERT_STRNE(cardDetails.surname().c_str(), "Pacquiao");
}

TEST_F(idpass_api_tests, cansign_and_verify_with_pin)
{
    std::string inputfile = std::string(datapath) + "manny1.bmp";
    std::ifstream f1(inputfile, std::ios::binary);
    std::vector<char> img1(std::istreambuf_iterator<char>{f1}, {});

    idpass::Dictionary pub_extras;
    idpass::Dictionary priv_extras;

    idpass::Pair *kv = pub_extras.add_pairs();
    kv->set_key("gender");
    kv->set_value("male");

    kv = priv_extras.add_pairs();
    kv->set_key("address");
    kv->set_value("16th Elm Street");

    std::vector<unsigned char> pubExtras(pub_extras.ByteSizeLong());
    std::vector<unsigned char> privExtras(priv_extras.ByteSizeLong());

    pub_extras.SerializeToArray(pubExtras.data(), pubExtras.size());
    priv_extras.SerializeToArray(privExtras.data(), privExtras.size());

    int ecard_len;
    unsigned char* ecard = idpass_api_create_card_with_face(
        ctx,
        &ecard_len,
        "Pacquiao",
        "Manny",
        dob_buf.data(), //"1980/12/25",
        dob_buf.size(),
        "Kibawe, Bukidnon",
        "12345",
        img1.data(),
        img1.size(),
        pubExtras.data(),
        pubExtras.size(),
        privExtras.data(),
        privExtras.size());

    idpass::IDPassCards cards;
    cards.ParseFromArray(ecard, ecard_len);
	unsigned char* e_card = (unsigned char*)cards.encryptedcard().c_str();
	int e_card_len = cards.encryptedcard().size();

    const char* data = "this is a test message";

    int signature_len;
    unsigned char* signature = idpass_api_sign_with_card(
        ctx,
        &signature_len,
		ecard,
		ecard_len,
        (unsigned char*)data,
        std::strlen(data));

    ASSERT_TRUE(signature != nullptr);

    int card_len;
    unsigned char* card = idpass_api_verify_card_with_pin(
        ctx, 
        &card_len, 
		ecard,
		ecard_len,
        "12345");

    idpass::CardDetails cardDetails;
    cardDetails.ParseFromArray(card, card_len);
    //std::cout << cardDetails.surname() << ", " << cardDetails.givenname() << std::endl;

    ASSERT_STREQ(cardDetails.surname().c_str(), "Pacquiao");
    ASSERT_STREQ(cardDetails.givenname().c_str(), "Manny");
}

TEST_F(idpass_api_tests, create_card_verify_with_face)
{
    std::string inputfile = std::string(datapath) + "manny1.bmp";
    std::ifstream f1(inputfile, std::ios::binary);
    std::vector<char> img1(std::istreambuf_iterator<char>{f1}, {});

    std::string inputfile2 = std::string(datapath) + "manny2.bmp";
    std::ifstream f2(inputfile2, std::ios::binary);
    std::vector<char> img2(std::istreambuf_iterator<char>{f2}, {});

    std::string inputfile3 = std::string(datapath) + "brad.jpg";
    std::ifstream f3(inputfile3, std::ios::binary);
    std::vector<char> img3(std::istreambuf_iterator<char>{f3}, {});

    idpass::Dictionary pub_extras;
    idpass::Dictionary priv_extras;

    idpass::Pair *kv = pub_extras.add_pairs();
    kv->set_key("gender");
    kv->set_value("male");

    kv = priv_extras.add_pairs();
    kv->set_key("address");
    kv->set_value("16th Elm Street");

    std::vector<unsigned char> pubExtras(pub_extras.ByteSizeLong());
    std::vector<unsigned char> privExtras(priv_extras.ByteSizeLong());

    pub_extras.SerializeToArray(pubExtras.data(), pubExtras.size());
    priv_extras.SerializeToArray(privExtras.data(), privExtras.size());

    int ecard_len;
    unsigned char* ecard = idpass_api_create_card_with_face(
        ctx,
        &ecard_len,
        "Pacquiao",
        "Manny",
        dob_buf.data(), //"1980/12/25",
        dob_buf.size(),
        "Kibawe, Bukidnon",
        "12345",
        img1.data(),
        img1.size(),
        pubExtras.data(),
        pubExtras.size(),
        privExtras.data(),
        privExtras.size());

    idpass::IDPassCards cards;
    cards.ParseFromArray(ecard, ecard_len);
	unsigned char* e_card =(unsigned char*)cards.encryptedcard().c_str();
	int e_card_len = cards.encryptedcard().size();

    int details_len;
    unsigned char* details = idpass_api_verify_card_with_face(
        ctx, &details_len, 
		ecard,
		ecard_len,
		img3.data(), img3.size());

    ASSERT_TRUE(nullptr == details); // different person's face should not verify

    details = idpass_api_verify_card_with_face(
        ctx, &details_len, 
		ecard, 
		ecard_len, 
		img2.data(), img2.size());

    ASSERT_TRUE(nullptr != details); // same person's face should verify

    idpass::CardDetails cardDetails;
    cardDetails.ParseFromArray(details, details_len);
    //std::cout << cardDetails.surname() << ", " << cardDetails.givenname() << std::endl;

	// Once verified, the details field should match
    ASSERT_STREQ(cardDetails.surname().c_str(), "Pacquiao");
    ASSERT_STREQ(cardDetails.givenname().c_str(), "Manny"); 
}

TEST_F(idpass_api_tests, threading_multiple_instance_test)
{
    const int N = 10;
    std::thread* T[N];

    for (int i = 0; i < N; i++) {
        T[i] = new std::thread(multiple_instance_test); 
    }
   
    std::for_each(T, T + N, [](std::thread* t) { 
        t->join(); 
        delete t;
    });
}

TEST_F(idpass_api_tests, threading_single_instance_test)
{
    const int N = 10;
    std::thread* T[N];

    for (int i = 0; i < N; i++) {
        T[i] = new std::thread(single_instance_test, ctx); 
    }
   
    std::for_each(T, T + N, [](std::thread* t) { 
        t->join(); 
        delete t;
    });
}

TEST_F(idpass_api_tests, face_template_test)
{
    std::string inputfile1 = std::string(datapath) + "manny1.bmp";
    std::string inputfile2 = std::string(datapath) + "manny2.bmp";

    std::ifstream f1(inputfile1, std::ios::binary);
    std::ifstream f2(inputfile2, std::ios::binary);

    std::vector<char> photo1(std::istreambuf_iterator<char>{f1}, {}); 
    std::vector<char> photo2(std::istreambuf_iterator<char>{f2}, {}); 

    float result_half = -10.0f;
    float result_full = -10.0f;
    int status;

    unsigned char photo1_template_full[128 * 4];
    unsigned char photo2_template_full[128 * 4];

    unsigned char photo1_template_half[64 * 2];
    unsigned char photo2_template_half[64 * 2];

    idpass_api_face128dbuf( ctx, photo1.data(), photo1.size(), photo1_template_full);
    idpass_api_face128dbuf( ctx, photo2.data(), photo2.size(), photo2_template_full);

    idpass_api_face64dbuf( ctx, photo1.data(), photo1.size(), photo1_template_half);
    idpass_api_face64dbuf( ctx, photo2.data(), photo2.size(), photo2_template_half);
    
    status = idpass_api_compare_face_template(
                                     photo1_template_full,
                                     sizeof photo1_template_full,
                                     photo2_template_full,
                                     sizeof photo2_template_full,
                                     &result_full); // 0.499922544

    ASSERT_TRUE(status == 0); 

    status = idpass_api_compare_face_template(
                                     photo1_template_half,
                                     sizeof photo1_template_half,
                                     photo2_template_half,
                                     sizeof photo2_template_half,
                                     &result_half); // 0.394599169
    ASSERT_TRUE(status == 0);                                     
}

int main (int argc, char *argv[])
{
    if (argc > 1) {
        datapath = argv[1];
    }
     
    struct stat statbuf;
    if (stat(datapath, &statbuf) != -1) {
        if (S_ISDIR(statbuf.st_mode)) {
           ::testing::InitGoogleTest(&argc, argv); 
            return RUN_ALL_TESTS();
        }
    }

    std::cout << "The data folder must exists relative to the executable's location\n";
    std::cout << "Or specify data path. For example:\n";
    std::cout << "./idpasstests lib/tests/data\n";
    return 0;
}
