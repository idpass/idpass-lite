#include "idpass.h"
#include "CCertificate.h"
#include "proto/api/api.pb.h"
#include "proto/idpasslite/idpasslite.pb.h"
#include "sodium.h"

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

class TestCases : public testing::Test
{
protected:
    void* ctx;
    unsigned char* m_enc;
    unsigned char* m_sig;
    unsigned char* m_ver;
    CCertificate* m_rootCert1;
    api::Ident m_ident;

    void SetUp() override
    {
        std::string filename = std::string(datapath) + "manny1.bmp";
        std::ifstream photofile(filename, std::ios::binary);
        std::vector<char> photo(std::istreambuf_iterator<char>{photofile}, {});

        m_ident.set_surname("Pacquiao");
        m_ident.set_givenname("Manny");
        m_ident.set_placeofbirth("Kibawe, Bukidnon");
        m_ident.set_pin("12345");
        m_ident.mutable_dateofbirth()->set_year(1978);
        m_ident.mutable_dateofbirth()->set_month(12);
        m_ident.mutable_dateofbirth()->set_day(17);
        m_ident.set_photo(photo.data(), photo.size());

        m_enc = new unsigned char[32];
        m_sig = new unsigned char[64];
        m_ver = new unsigned char[32];
        m_rootCert1 = new CCertificate();

        api::KeySet cryptoKeys;

        idpass_lite_generate_secret_signature_key(m_sig, 64);
        idpass_lite_generate_encryption_key(m_enc, 32);
        std::memcpy(m_ver, m_sig + 32, 32);

        cryptoKeys.set_encryptionkey(m_enc, 32);
        cryptoKeys.set_signaturekey(m_sig, 64);
        api::byteArray* verkey = cryptoKeys.add_verificationkeys();
        verkey->set_typ(api::byteArray_Typ_ED25519PUBKEY);
        verkey->set_val(m_ver, 32);

        std::vector<unsigned char> buf1;

        buf1.resize(cryptoKeys.ByteSizeLong());
        cryptoKeys.SerializeToArray(buf1.data(),
                                    buf1.size());

        CCertificate rootCert2;
        CCertificate rootCert3;

        api::Certificates rootCertificates;
        api::Certificate* cert1 = rootCertificates.add_cert();
        api::Certificate* cert2 = rootCertificates.add_cert();
        api::Certificate* cert3 = rootCertificates.add_cert();
        cert1->CopyFrom(m_rootCert1->getValue(true));
        cert2->CopyFrom(rootCert2.getValue(true));
        cert3->CopyFrom(rootCert3.getValue(true));
        std::vector<unsigned char> buf2(rootCertificates.ByteSizeLong());
        rootCertificates.SerializeToArray(buf2.data(), buf2.size());

        ctx = idpass_lite_init(
            buf1.data(), buf1.size(), buf2.data(), buf2.size());

        ASSERT_TRUE(ctx != nullptr);
    }

    void TearDown() override
    {
        delete[] m_enc;
        delete[] m_sig;
        delete[] m_ver;
        delete m_rootCert1;
    }
};

TEST_F(TestCases, create_card_with_certificates_content_tampering)
{
    std::string inputfile = std::string(datapath) + "manny1.bmp";
    std::ifstream f1(inputfile, std::ios::binary);
    std::vector<char> photo(std::istreambuf_iterator<char>{f1}, {});

    unsigned char ioctlcmd[] = {IOCTL_SET_ACL,
                                ACL_SURNAME  | ACL_PLACEOFBIRTH };

    idpass_lite_ioctl(ctx, nullptr, ioctlcmd, sizeof ioctlcmd);

    std::vector<unsigned char> buf(m_ident.ByteSizeLong());
    m_ident.SerializeToArray(buf.data(), buf.size());
    
    int len;
    unsigned char* cards
        = idpass_lite_create_card_with_face(ctx, &len, buf.data(), buf.size());

    ASSERT_TRUE(cards != nullptr);

    idpass::IDPassCards idpassCards;
    ASSERT_TRUE(idpassCards.ParseFromArray(cards, len));

    idpass::PublicSignedIDPassCard publicRegion = idpassCards.publiccard();

    ASSERT_STREQ(publicRegion.details().surname().c_str(), "Pacquiao");
    ASSERT_STREQ(publicRegion.details().placeofbirth().c_str(),
                 "Kibawe, Bukidnon");

    idpass::PublicSignedIDPassCard publicRegion_tampered;
    idpass::CardDetails details_tampered;
    details_tampered.set_placeofbirth("Kibawe,Bukidnon");
    publicRegion_tampered.mutable_details()->CopyFrom(details_tampered);

    idpassCards.mutable_publiccard()->CopyFrom(publicRegion_tampered);

    int n = idpassCards.ByteSizeLong();
    std::vector<unsigned char> tampered(n);
    ASSERT_TRUE(idpassCards.SerializeToArray(tampered.data(), n));

    int details_len = 0;
    unsigned char* details = idpass_lite_verify_card_with_face(ctx,
                                                               &details_len,
                                                               tampered.data(),
                                                               tampered.size(),
                                                               photo.data(),
                                                               photo.size());

    ASSERT_TRUE(details == nullptr);
}

TEST_F(TestCases, idpass_lite_create_card_with_face_certificates)
{
    std::string filename = std::string(datapath) + "manny1.bmp";
    std::ifstream photofile(filename, std::ios::binary);
    std::vector<char> photo(std::istreambuf_iterator<char>{photofile}, {});

    std::vector<unsigned char> ident_buf(m_ident.ByteSizeLong());
    m_ident.SerializeToArray(ident_buf.data(), ident_buf.size());

    int n;

    CCertificate child0;
    CCertificate child1(m_sig, 64);
    m_rootCert1->Sign(child0);
    child0.Sign(child1);

    api::Certificates intermediateCertificates;
    api::Certificate* c1 = intermediateCertificates.add_cert();
    c1->CopyFrom(child0.getValue());
    api::Certificate* c2 = intermediateCertificates.add_cert();
    c2->CopyFrom(child1.getValue());

    std::vector<unsigned char> intermedcerts_buf(intermediateCertificates.ByteSizeLong());

    intermediateCertificates.SerializeToArray(intermedcerts_buf.data(),
                                              intermedcerts_buf.size());

    n = idpass_lite_add_certificates(
        ctx, intermedcerts_buf.data(), intermedcerts_buf.size());

    ASSERT_TRUE(n == 0); // 0 means no error

    /*
    Create an ID for the person details in the ident structure. This
    returns a deserialized idpass::IDPassCards protobuf message.
    */

    int buf_len = 0;
    unsigned char* buf = idpass_lite_create_card_with_face(
        ctx, &buf_len, ident_buf.data(), ident_buf.size());

    ASSERT_TRUE(buf != nullptr);

    /*
    Construct idpass::IDPassCards from the returned byte[]
    */

    idpass::IDPassCards cards;
    ASSERT_TRUE(cards.ParseFromArray(buf, buf_len));

    /*
    List certificates
    */

    ASSERT_TRUE(cards.certificates_size() == 2);

    std::vector<idpass::Certificate> chain;

    for (auto& c : cards.certificates()) {
        chain.push_back(c);
    }

    ASSERT_TRUE(std::memcmp(chain[0].pubkey().data(), child0.value.pubkey().data(), 32) == 0);
    ASSERT_TRUE(std::memcmp(chain[1].pubkey().data(), child1.value.pubkey().data(), 32) == 0);

    /*
    Present the user's ID and if the face match, will return
    the person's details.
    */

    int details_len = 0;
    unsigned char* details = idpass_lite_verify_card_with_face(
        ctx, &details_len, buf, buf_len, photo.data(), photo.size());

    ASSERT_TRUE(details != nullptr);
}

TEST_F(TestCases, cannot_add_intermed_cert_without_rootcert)
{
    CCertificate cert0;
    CCertificate cert1;
    
    cert1.setPublicKey(m_ver, 32); // very important
    cert0.Sign(cert1);
    m_rootCert1->Sign(cert1);

    api::Certificates intermedcerts;
    intermedcerts.add_cert()->CopyFrom(cert0.value);
    intermedcerts.add_cert()->CopyFrom(cert1.value);

    std::vector<unsigned char> buf(intermedcerts.ByteSizeLong());
    intermedcerts.SerializeToArray(buf.data(), buf.size());

    api::KeySet keyset;
    unsigned char enc[32];
    unsigned char sig[64];
    unsigned char ver[32];

    idpass_lite_generate_secret_signature_key(sig, 64);
    idpass_lite_generate_encryption_key(enc, 32);
    std::memcpy(ver, sig + 32, 32);

    keyset.set_encryptionkey(enc, 32);
    keyset.set_signaturekey(sig, 64);
    api::byteArray* verkey = keyset.add_verificationkeys();
    verkey->set_typ(api::byteArray_Typ_ED25519PUBKEY);
    verkey->set_val(ver, 32);

    std::vector<unsigned char> _keyset(keyset.ByteSizeLong());
    keyset.SerializeToArray(_keyset.data(), _keyset.size());

    void* context
        = idpass_lite_init(_keyset.data(), _keyset.size(), nullptr, 0);

    // have surname visible in public region so we can do quick check below
    unsigned char ioctlcmd[] = {IOCTL_SET_ACL,
                                ACL_SURNAME  | ACL_PLACEOFBIRTH };
    idpass_lite_ioctl(context, nullptr, ioctlcmd, sizeof ioctlcmd);


    // should still initialize even without rootcerts
    ASSERT_TRUE(context != nullptr);     

    // cannot add intermed certs without rootcerts
    ASSERT_TRUE(0 != idpass_lite_add_certificates(context, 
        buf.data(), buf.size())); 

    std::vector<unsigned char> _ident(m_ident.ByteSizeLong());
    m_ident.SerializeToArray(_ident.data(), _ident.size());

    int card_len = 0;
    unsigned char* card = idpass_lite_create_card_with_face(
        context, &card_len, _ident.data(), _ident.size());

    // can still create cards without root certs and intermed certs
    EXPECT_TRUE(card != nullptr);
    idpass::IDPassCards fullcard;
    EXPECT_TRUE(fullcard.ParseFromArray(card, card_len));
    
    // rough check that card is created by checking surname field
    ASSERT_TRUE(fullcard.publiccard().details().surname().compare("Pacquiao")
                == 0);

    // and the created card shall have no certificate content
    ASSERT_TRUE(fullcard.certificates_size() == 0);
}

TEST_F(TestCases, idpass_lite_verify_certificate)
{
    CCertificate cert0;
    CCertificate cert1;
    
    cert1.setPublicKey(m_ver, 32); // very important
    cert0.Sign(cert1);
    m_rootCert1->Sign(cert1);

    api::Certificates intermedcerts;
    intermedcerts.add_cert()->CopyFrom(cert0.value);
    intermedcerts.add_cert()->CopyFrom(cert1.value);

    std::vector<unsigned char> buf(intermedcerts.ByteSizeLong());
    intermedcerts.SerializeToArray(buf.data(), buf.size());

    ASSERT_TRUE(0 == idpass_lite_add_certificates(ctx, buf.data(), buf.size()));

    std::vector<unsigned char> _ident(m_ident.ByteSizeLong());
    m_ident.SerializeToArray(_ident.data(), _ident.size());
    
    int cards_len = 0;
    unsigned char* cards
        = idpass_lite_create_card_with_face(ctx, &cards_len, _ident.data(), _ident.size());

    ASSERT_TRUE(cards != nullptr);
    ASSERT_EQ(idpass_lite_verify_certificate(ctx, cards, cards_len), 2); // 2 certs

    idpass::IDPassCards fullcard;
    ASSERT_TRUE(fullcard.ParseFromArray(cards, cards_len));

    std::vector<idpass::Certificate> cardcerts(fullcard.certificates().begin(),
                                               fullcard.certificates().end());

    ASSERT_TRUE(std::memcmp(cardcerts[0].pubkey().data(), cert0.value.pubkey().data(), 32) == 0);
    ASSERT_TRUE(std::memcmp(cardcerts[1].pubkey().data(), cert1.value.pubkey().data(), 32) == 0);
}

TEST_F(TestCases, idpass_lite_init_test)
{
    unsigned char enc[32];
    unsigned char sig[64];
    unsigned char ver[32];

    idpass_lite_generate_secret_signature_key(sig, 64);
    idpass_lite_generate_encryption_key(enc, 32);
    std::memcpy(ver, sig + 32, 32);

    void* context = nullptr;

    api::KeySet cryptoKeys;
    api::Certificates rootCerts;

    std::vector<unsigned char> cryptokeys_buf;
    std::vector<unsigned char> rootcerts_buf;

    context = idpass_lite_init(cryptokeys_buf.data(),
                               cryptokeys_buf.size(),
                               rootcerts_buf.data(),
                               rootcerts_buf.size());

    ASSERT_TRUE(context == nullptr);

    cryptoKeys.set_encryptionkey(enc, 32);
    cryptoKeys.set_signaturekey(sig, 64);
    api::byteArray* verkey = cryptoKeys.add_verificationkeys();
    verkey->set_typ(api::byteArray_Typ_ED25519PUBKEY);
    verkey->set_val(ver, 32);

    cryptokeys_buf.resize(cryptoKeys.ByteSizeLong());
    cryptoKeys.SerializeToArray(cryptokeys_buf.data(), cryptokeys_buf.size());

    context = idpass_lite_init(cryptokeys_buf.data(),
                               cryptokeys_buf.size(),
                               rootcerts_buf.data(),
                               rootcerts_buf.size());

    ASSERT_TRUE(context != nullptr); // make rootcerts optional

    CCertificate rootCA;

    api::Certificate* pcer = rootCerts.add_cert();
    pcer->CopyFrom(rootCA.getValue(true));
    rootcerts_buf.resize(rootCerts.ByteSizeLong());
    rootCerts.SerializeToArray(rootcerts_buf.data(), rootcerts_buf.size());

    context = idpass_lite_init(cryptokeys_buf.data(),
                               cryptokeys_buf.size(),
                               rootcerts_buf.data(),
                               rootcerts_buf.size());

    ASSERT_TRUE(context != nullptr);
}

TEST_F(TestCases, idpass_lite_create_card_with_face_test)
{
    api::Ident ident;

    std::vector<unsigned char> ident_buf(ident.ByteSizeLong());
    ident.SerializeToArray(ident_buf.data(), ident_buf.size());

    int buf_len = 0;
    unsigned char* buf = idpass_lite_create_card_with_face(
        ctx, &buf_len, ident_buf.data(), ident_buf.size());

    ASSERT_TRUE(buf == nullptr); // because ident has no photo

    std::string filename = std::string(datapath) + "manny1.bmp";
    std::ifstream photofile(filename, std::ios::binary);
    std::vector<char> photo(std::istreambuf_iterator<char>{photofile}, {});

    unsigned char ioctlcmd[]
        = {IOCTL_SET_ACL, ACL_PLACEOFBIRTH | ACL_GIVENNAME};

    idpass_lite_ioctl(ctx, nullptr, ioctlcmd, sizeof ioctlcmd);

    api::KV* kv = m_ident.add_pubextra();
    kv->set_key("gender");
    kv->set_value("male");

    ident_buf.resize(m_ident.ByteSizeLong());
    m_ident.SerializeToArray(ident_buf.data(), ident_buf.size());

    buf = idpass_lite_create_card_with_face(
        ctx, &buf_len, ident_buf.data(), ident_buf.size());

    ASSERT_TRUE(buf != nullptr);

    idpass::IDPassCards cards;
    ASSERT_TRUE(cards.ParseFromArray(buf, buf_len));

    int details_len = 0;
    unsigned char* details = idpass_lite_verify_card_with_face(
        ctx, &details_len, buf, buf_len, photo.data(), photo.size());

    ASSERT_TRUE(details != nullptr);
}

TEST_F(TestCases, generate_secretsignature_key)
{
    unsigned char sig[crypto_sign_SECRETKEYBYTES]; // 64
    unsigned char sig2[63];
    int status;

    status = idpass_lite_generate_secret_signature_key(sig, sizeof sig);
    ASSERT_TRUE(status == 0);
    status = idpass_lite_generate_secret_signature_key(sig2, sizeof sig2);
    ASSERT_TRUE(status != 0);
}

TEST_F(TestCases, generate_encryption_key)
{
    unsigned char enc[crypto_aead_chacha20poly1305_IETF_KEYBYTES]; // 32
    unsigned char enc2[31];
    int status;

    status = idpass_lite_generate_encryption_key(enc, sizeof enc);
    ASSERT_TRUE(status == 0);
    status = idpass_lite_generate_encryption_key(enc2, sizeof enc2);
    ASSERT_TRUE(status != 0);
}

TEST_F(TestCases, chain_of_trust_test)
{
    auto verify_chain = [this](std::vector<CCertificate>& chain, bool expected) {
        int status;
        api::Certificates chaincerts;
        for (auto& c : chain) {
            api::Certificate* pCer = chaincerts.add_cert();
            pCer->CopyFrom(c.value);
        }
        std::vector<unsigned char> buf(chaincerts.ByteSizeLong());
        chaincerts.SerializeToArray(buf.data(), buf.size());
        status = idpass_lite_add_certificates(ctx, buf.data(), buf.size());
        return status == expected ? 0 : 1;
    };

    unsigned char secret_sig_key[64];
    idpass_lite_generate_secret_signature_key(secret_sig_key, 64);

    CCertificate cert2_rootca;
    CCertificate cert7_cert2(secret_sig_key, 64);

    m_rootCert1->Sign(cert2_rootca);
    cert2_rootca.Sign(cert7_cert2);

    std::vector<CCertificate> chain2_valid{cert2_rootca, cert7_cert2};
    ASSERT_TRUE(verify_chain(chain2_valid, true));

    CCertificate c01_c03; // self-signed during creation
    CCertificate c02_c01;
    CCertificate c03_c02;
    c01_c03.Sign(c02_c01);
    c02_c01.Sign(c03_c02);
    c03_c02.Sign(c01_c03); // make it circular

    std::vector<CCertificate> chain_invalid_circular{ c01_c03, c02_c01, c03_c02 };
    ASSERT_TRUE(verify_chain(chain_invalid_circular, false));

    CCertificate gamma;
    CCertificate cert8_gamma;
    gamma.Sign(cert8_gamma);
 
    std::vector<CCertificate> chain12_invalid{gamma, cert8_gamma};
    ASSERT_TRUE(verify_chain(chain12_invalid, false));

    m_rootCert1->Sign(gamma);
    std::vector<CCertificate> chain_valid{gamma, cert8_gamma};
    ASSERT_TRUE(verify_chain(chain_valid, true));

    CCertificate cert001(secret_sig_key, 64);
    m_rootCert1->Sign(cert001);
    std::vector<CCertificate> chain_1{cert001};
    ASSERT_TRUE(verify_chain(chain_1, true));

    CCertificate cert002(secret_sig_key, 64);
    std::vector<CCertificate> chain_2{cert002};
    ASSERT_TRUE(verify_chain(chain_2, false));
}

TEST_F(TestCases, create_card_with_certificates)
{
    CCertificate certifi;
    certifi.setPublicKey(m_ver, 32);

    ASSERT_FALSE(certifi.isSelfSigned());
    ASSERT_FALSE(certifi.hasValidSignature());

    m_rootCert1->Sign(certifi);

    ASSERT_TRUE(certifi.hasValidSignature());
    ASSERT_FALSE(certifi.isSelfSigned());

    api::Certificates intermedCerts;
    api::Certificate* pCer = intermedCerts.add_cert();
    pCer->CopyFrom(certifi.getValue()); 

    std::vector<unsigned char> buf(intermedCerts.ByteSizeLong());
    intermedCerts.SerializeToArray(buf.data(), buf.size());

    ASSERT_TRUE(idpass_lite_add_certificates(ctx, buf.data(), buf.size()) == 0);

    // transfer givenname, placeofbirth to public region
    // thus, these fields will no longer be in the private region
    // this is to avoid redundancy 
    unsigned char ioctlcmd[] = { IOCTL_SET_ACL, 
        ACL_PLACEOFBIRTH | ACL_GIVENNAME }; 
    idpass_lite_ioctl(ctx, nullptr, ioctlcmd, sizeof ioctlcmd);

    int ecard_len;
    unsigned char* ecard;

    std::vector<unsigned char> ident(m_ident.ByteSizeLong());
    m_ident.SerializeToArray(ident.data(), ident.size());

    ecard = idpass_lite_create_card_with_face(
        ctx, &ecard_len, ident.data(), ident.size());

    ASSERT_TRUE(ecard != nullptr);

    idpass::IDPassCards cards;
    ASSERT_TRUE(cards.ParseFromArray(ecard, ecard_len));

    bool found = false;
    idpass::Certificate certi;
    for (auto& c : cards.certificates()) {
        if (0 == std::memcmp(c.pubkey().data(), 
            certifi.value.pubkey().data(), 32)) 
        {
            found = true; 
        }
    }

    ASSERT_TRUE(found);

    int details_len = 0;
    unsigned char* details = idpass_lite_verify_card_with_pin(
        ctx, &details_len, ecard, ecard_len, "12345");

    ASSERT_TRUE(details != nullptr);
}

TEST_F(TestCases, check_qrcode_md5sum)
{
    auto savetobitmap = [](int qrcode_size,
                           unsigned char* pixelbits,
                           const char* outfile = "/tmp/qrcode.bmp") {
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
    };

    int card_len;
    unsigned char* card;

    std::vector<unsigned char> identbuf(m_ident.ByteSizeLong());
    m_ident.SerializeToArray(identbuf.data(), identbuf.size());

    card = idpass_lite_create_card_with_face(
        ctx, &card_len, identbuf.data(), identbuf.size());

    ASSERT_TRUE(card != nullptr);
    idpass::IDPassCards cards;
    ASSERT_TRUE(cards.ParseFromArray(card, card_len));

    int qrsize = 0;
    unsigned char* pixel = idpass_lite_qrpixel(
        ctx,
        card,
        card_len,
        &qrsize);

    ASSERT_TRUE(pixel != nullptr);

#ifdef _WIN32
        FILE *fp = fopen("c:/Users/63927/Documents/qrcode.dat", "wb");
#else
        FILE *fp = fopen("/tmp/qrcode.dat", "wb");
#endif
        int nwritten = 0;
        nwritten = fwrite(card , 1, card_len, fp);
        while (nwritten < card_len) {
            nwritten += fwrite(card , 1, card_len + nwritten, fp);
        }
        fclose(fp);

#ifdef _WIN32
        savetobitmap(qrsize, pixel, "c:/Users/63927/Documents/qrcode.bmp");
#else
        savetobitmap(qrsize, pixel, "qrcode.bmp");
#endif
}

TEST_F(TestCases, createcard_manny_verify_as_brad)
{
    std::string inputfile = std::string(datapath) + "manny1.bmp";
    std::ifstream f1(inputfile, std::ios::binary);
    std::vector<char> img1(std::istreambuf_iterator<char>{f1}, {});

    std::string inputfile2 = std::string(datapath) + "brad.jpg";
    std::ifstream f2(inputfile2, std::ios::binary);
    std::vector<char> img3(std::istreambuf_iterator<char>{f2}, {});

    int ecard_len = 0;
    unsigned char* ecard;

    std::vector<unsigned char> identbuf(m_ident.ByteSizeLong());
    m_ident.SerializeToArray(identbuf.data(), identbuf.size());

    ecard = idpass_lite_create_card_with_face(
        ctx, &ecard_len, identbuf.data(), identbuf.size());

    ASSERT_TRUE(ecard != nullptr);

    int details_len;
    unsigned char* details = idpass_lite_verify_card_with_face(
        ctx, 
        &details_len, 
        ecard, 
        ecard_len, 
        img3.data(), 
        img3.size()
        );

    ASSERT_TRUE(details == nullptr);

    details = idpass_lite_verify_card_with_face(
        ctx, 
        &details_len, 
        ecard, 
        ecard_len, 
        img1.data(), 
        img1.size()
        );

    ASSERT_TRUE(details != nullptr);

    idpass::CardDetails cardDetails;
    cardDetails.ParseFromArray(details, details_len);
    ASSERT_STREQ(cardDetails.surname().c_str(), "Pacquiao");
}

TEST_F(TestCases, cansign_and_verify_with_pin)
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

    int ecard_len = 0;
    unsigned char* ecard;

    std::vector<unsigned char> identbuf(m_ident.ByteSizeLong());
    m_ident.SerializeToArray(identbuf.data(), identbuf.size());

    ecard = idpass_lite_create_card_with_face(
        ctx,
        &ecard_len,
        identbuf.data(), identbuf.size());

    ASSERT_TRUE(ecard != nullptr);

    idpass::IDPassCards cards;
    ASSERT_TRUE(cards.ParseFromArray(ecard, ecard_len));

    const char* data = "this is a test message";

    int signature_len;
    unsigned char* signature = idpass_lite_sign_with_card(
        ctx,
        &signature_len,
		ecard,
		ecard_len,
        (unsigned char*)data,
        std::strlen(data));

    ASSERT_TRUE(signature != nullptr);

    int card_len;
    unsigned char* card = idpass_lite_verify_card_with_pin(
        ctx, 
        &card_len, 
		ecard,
		ecard_len,
        "12345");

    ASSERT_TRUE(card != nullptr);

    idpass::CardDetails cardDetails;
    cardDetails.ParseFromArray(card, card_len);
    //std::cout << cardDetails.surname() << ", " << cardDetails.givenname() << std::endl;

    ASSERT_STREQ(cardDetails.surname().c_str(), "Pacquiao");
    ASSERT_STREQ(cardDetails.givenname().c_str(), "Manny");
}

TEST_F(TestCases, create_card_verify_with_face)
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

    int ecard_len;
    unsigned char* ecard;

    std::vector<unsigned char> ident(m_ident.ByteSizeLong());
    m_ident.SerializeToArray(ident.data(), ident.size());

    ecard = idpass_lite_create_card_with_face(
        ctx, &ecard_len, ident.data(), ident.size());

    ASSERT_TRUE(ecard != nullptr);

    idpass::IDPassCards cards;
    cards.ParseFromArray(ecard, ecard_len);
	unsigned char* e_card =(unsigned char*)cards.encryptedcard().c_str();
	int e_card_len = cards.encryptedcard().size();

    int details_len;
    unsigned char* details = idpass_lite_verify_card_with_face(
        ctx, &details_len, 
		ecard,
		ecard_len,
		img3.data(), img3.size());

    ASSERT_TRUE(nullptr == details); // different person's face should not verify

    details = idpass_lite_verify_card_with_face(
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

TEST_F(TestCases, threading_multiple_instance_test)
{
    // Multiple different instances of idpass_lite_init contexts
    auto multiple_instance_test = [this]()
    {
        unsigned char enc[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
        unsigned char sig_skpk[crypto_sign_SECRETKEYBYTES];
        unsigned char verif_pk[crypto_sign_PUBLICKEYBYTES];

        idpass_lite_generate_encryption_key(enc, 32);
        idpass_lite_generate_secret_signature_key(sig_skpk, 64);
        std::memcpy(verif_pk, sig_skpk + 32, crypto_sign_PUBLICKEYBYTES);

        api::KeySet ks;
        ks.set_encryptionkey(enc, 32);
        ks.set_signaturekey(sig_skpk, 64);
        api::byteArray* verkey = ks.add_verificationkeys();
        verkey->set_typ(api::byteArray_Typ_ED25519PUBKEY);
        verkey->set_val(verif_pk, 32);

        CCertificate rootCert1;
        CCertificate rootCert2;

        api::Certificates rootCertificates;
        api::Certificate* content1 = rootCertificates.add_cert();
        api::Certificate* content2 = rootCertificates.add_cert();
        content1->CopyFrom(rootCert1.value);
        content2->CopyFrom(rootCert1.value);

        CCertificate intermedCert1;
        CCertificate intermedCert2;
        intermedCert2.setPublicKey(verif_pk, 32);
        intermedCert1.Sign(intermedCert2);
        rootCert1.Sign(intermedCert1);

        std::vector<unsigned char> rootcertsbuf(
            rootCertificates.ByteSizeLong());
        rootCertificates.SerializeToArray(rootcertsbuf.data(),
                                          rootcertsbuf.size());
        std::vector<unsigned char> keysetbuf(ks.ByteSizeLong());
        ks.SerializeToArray(keysetbuf.data(), keysetbuf.size());

        void* context = idpass_lite_init(keysetbuf.data(),
                                         keysetbuf.size(),
                                         rootcertsbuf.data(),
                                         rootcertsbuf.size());
        ASSERT_TRUE(context != nullptr);

        std::string inputfile = std::string(datapath) + "manny1.bmp";
        std::ifstream f1(inputfile, std::ios::binary);
        ASSERT_TRUE(f1.is_open());

        std::vector<char> photo(std::istreambuf_iterator<char>{f1}, {});
        int card_len = 0;
        unsigned char* card;

        std::vector<unsigned char> identbuf(m_ident.ByteSizeLong());
        m_ident.SerializeToArray(identbuf.data(), identbuf.size());

        card = idpass_lite_create_card_with_face(
            context, &card_len, identbuf.data(), identbuf.size());

        ASSERT_TRUE(card != nullptr);

        idpass::IDPassCards cards;
        ASSERT_TRUE(cards.ParseFromArray(card, card_len));

        int buf_len;
        unsigned char* buf = idpass_lite_verify_card_with_face(
            context, &buf_len, card, card_len, photo.data(), photo.size());

        ASSERT_TRUE(buf != nullptr);
        
        idpass::CardDetails userDetails;
        ASSERT_TRUE(userDetails.ParseFromArray(buf, buf_len));
    };

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

TEST_F(TestCases, threading_single_instance_test)
{
    // A single instance of idpass_api_init context
    // called in multiple threads
    auto single_instance_test = [this](void* ctx)
    {
        std::string inputfile = std::string(datapath) + "manny1.bmp";
        std::ifstream f1(inputfile, std::ios::binary);
        ASSERT_TRUE(f1.is_open());

        std::vector<char> photo(std::istreambuf_iterator<char>{f1}, {});

        unsigned char ioctlcmd[]
            = {IOCTL_SET_ACL,
               ACL_PLACEOFBIRTH
                   | ACL_GIVENNAME}; // make givenname, placeofbirth visible

        idpass_lite_ioctl(ctx, nullptr, ioctlcmd, sizeof ioctlcmd);

        std::vector<unsigned char> identbuf(m_ident.ByteSizeLong());
        m_ident.SerializeToArray(identbuf.data(), identbuf.size());

        int card_len;
        unsigned char* card = idpass_lite_create_card_with_face(
            ctx, &card_len, identbuf.data(), identbuf.size());

        ASSERT_TRUE(card != nullptr);

        idpass::IDPassCards cards;
        ASSERT_TRUE(cards.ParseFromArray(card, card_len));

        ASSERT_TRUE(cards.publiccard().details().surname().empty());
        ASSERT_TRUE(cards.publiccard().details().givenname().compare("Manny")
                    == 0);
        ASSERT_TRUE(cards.publiccard().details().dateofbirth().ByteSizeLong()
                    == 0);
        ASSERT_TRUE(cards.publiccard().details().placeofbirth().compare(
                        "Kibawe, Bukidnon")
                    == 0);

        int buf_len;
        unsigned char* buf = idpass_lite_verify_card_with_face(
            ctx, &buf_len, card, card_len, photo.data(), photo.size());

        ASSERT_TRUE(buf != nullptr);

        idpass::CardDetails details;
        ASSERT_TRUE(details.ParseFromArray(buf, buf_len));
    };

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

TEST_F(TestCases, face_template_test)
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

    idpass_lite_face128dbuf( ctx, photo1.data(), photo1.size(), photo1_template_full);
    idpass_lite_face128dbuf( ctx, photo2.data(), photo2.size(), photo2_template_full);

    idpass_lite_face64dbuf( ctx, photo1.data(), photo1.size(), photo1_template_half);
    idpass_lite_face64dbuf( ctx, photo2.data(), photo2.size(), photo2_template_half);
    
    status = idpass_lite_compare_face_template(
                                     photo1_template_full,
                                     sizeof photo1_template_full,
                                     photo2_template_full,
                                     sizeof photo2_template_full,
                                     &result_full); // 0.499922544

    ASSERT_TRUE(status == 0); 

    status = idpass_lite_compare_face_template(
                                     photo1_template_half,
                                     sizeof photo1_template_half,
                                     photo2_template_half,
                                     sizeof photo2_template_half,
                                     &result_half); // 0.394599169
    ASSERT_TRUE(status == 0);                                     
}

TEST_F(TestCases, uio_test)
{
    unsigned char* buf = idpass_lite_uio(ctx, 0);
    int len;
    std::memcpy(&len, buf, sizeof(int));
    api::Ident ident;
    ASSERT_TRUE(ident.ParseFromArray(buf + sizeof(int), len));
    ASSERT_TRUE(0 == ident.surname().compare("Doe"));
    ASSERT_TRUE(0 == ident.givenname().compare("John"));
}

int main(int argc, char* argv[])
{
    if (argc > 1) {
        datapath = argv[1];
    }

    struct stat statbuf;
    if (stat(datapath, &statbuf) != -1) {
        if (S_ISDIR(statbuf.st_mode)) {
            ::testing::InitGoogleTest(&argc, argv);
            //::testing::GTEST_FLAG(filter) = "*uio_test*";
            //::testing::GTEST_FLAG(filter) = "*createcard_manny_verify_as_brad*";
            //::testing::GTEST_FLAG(filter) = "*threading_multiple_instance_test*";
            return RUN_ALL_TESTS();
        }
    }

    std::cout
        << "The data folder must exists relative to the executable's location\n";
    std::cout << "Or specify data path. For example:\n";
    std::cout << "./idpasstests lib/tests/data\n";
    return 0;
}
