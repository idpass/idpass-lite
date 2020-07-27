//=============================================================================
// This file should not contain Dlib nor libsodium logic. This file should only
// contain JNI stuff. 
// 
// For example, I was about to put key length checks here in the idpass_init
// function. This would mean I will include here sodium.h and will entagle
// the core logic in idpass.cpp. 
// 
// The only logic in this file and header shall only be pure JNI 

#include "../../../idpass.h"

#include <jni.h>

#include <iostream>
#include <string>
#include <cstring>

#ifdef ANDROID
#include <android/log.h>

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "idpass_jni::C++", __VA_ARGS__))
#else
#define LOGI(...)
#endif

jlong
idpass_init(JNIEnv *env,
            jobject thiz,
            jbyteArray enc,
            jbyteArray sig,
            jbyteArray verif,
            jobjectArray rootcertificates)
{
    jbyte *bufEnc = env->GetByteArrayElements(enc, 0);
    jsize bufEnc_len = env->GetArrayLength(enc);

    jbyte *bufSig = env->GetByteArrayElements(sig, 0);
    jsize bufSig_len = env->GetArrayLength(sig);

    jbyte *bufVerif = env->GetByteArrayElements(verif, 0);
    jsize bufVerif_len = env->GetArrayLength(verif);

    //////////////////
    int count = rootcertificates != nullptr ? env->GetArrayLength(rootcertificates) : 0;

    unsigned char **cert = nullptr;
    int *nlen = nullptr;

    if (count > 0) {
        cert = new unsigned char *[count];
        nlen = new int[count];
    }

    for (int i = 0; i < count; i++) {
        jbyteArray jba = (jbyteArray)env->GetObjectArrayElement(rootcertificates, i);
        jbyte *buf = env->GetByteArrayElements(jba, 0);
        int buf_len = env->GetArrayLength(jba);
        nlen[i] = buf_len;
        cert[i] = new unsigned char[buf_len];
        std::memcpy(cert[i], buf, buf_len);
        env->ReleaseByteArrayElements(jba, buf, JNI_ABORT);
        env->DeleteLocalRef(jba);
    }

    void *ctx = idpass_api_init(reinterpret_cast<unsigned char *>(bufEnc),
                                bufEnc_len,
                                reinterpret_cast<unsigned char *>(bufSig),
                                bufSig_len,
                                reinterpret_cast<unsigned char *>(bufVerif),
                                bufVerif_len,
                                cert,
                                nlen,
                                count);
    // clean-up
    if (count > 0) {
        for (int i = 0; i < count; i++) {
            delete[] cert[i];
        }

        delete[] cert;
        delete[] nlen;
    }
    //////////////////

    env->ReleaseByteArrayElements(enc, bufEnc, 0);
    env->ReleaseByteArrayElements(sig, bufSig, 0);
    env->ReleaseByteArrayElements(verif, bufVerif, 0);

    if (ctx) {
        LOGI("idpass_api_init ok");
        return reinterpret_cast<long>(ctx); // no error
    } else {
        LOGI("idpass_api_init fail: sodium_init");
        return 0; 
    }
}

jbyteArray 
ioctl(JNIEnv *env,
      jobject thiz,
      jlong context,
      jbyteArray iobuf)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    jbyte *buf = env->GetByteArrayElements(iobuf, 0);
    jsize buf_len = env->GetArrayLength(iobuf);

    idpass_api_ioctl(ctx, nullptr, 
        reinterpret_cast<unsigned char *>(buf), buf_len);

    env->ReleaseByteArrayElements(iobuf, buf, 0);
    return env->NewByteArray(0);
}

jbyteArray 
create_card_with_face(JNIEnv *env,
                      jobject thiz,
                      jlong context,
                      jstring sur_name,
                      jstring given_name,
                      jstring date_of_birth,
                      jstring place_of_birth,
                      jstring pin,
                      jbyteArray photo,
                      jbyteArray pub_extras,
                      jbyteArray priv_extras)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    jbyteArray ecard = nullptr;
    jbyte *buf = env->GetByteArrayElements(photo, 0);
    jsize buf_len = env->GetArrayLength(photo);

    if (buf_len == 0) {
        LOGI("null photo");
        return env->NewByteArray(0);
    }

    const char *bufSurname = sur_name? env->GetStringUTFChars(sur_name, 0) : "";
    const char *bufGivenName = given_name? env->GetStringUTFChars(given_name, 0) : "";
    const char *bufDateOfBirth = date_of_birth? env->GetStringUTFChars(date_of_birth, 0) : "";
    const char *bufPlaceOfBirth = place_of_birth? env->GetStringUTFChars(place_of_birth, 0) : "";
    const char *bufPin = pin? env->GetStringUTFChars(pin, 0) : "";

    jbyte *pub_extras_buf = env->GetByteArrayElements(pub_extras, 0);
    jsize pub_extras_buf_len = env->GetArrayLength(pub_extras);

    jbyte *priv_extras_buf = env->GetByteArrayElements(priv_extras, 0);
    jsize priv_extras_buf_len = env->GetArrayLength(priv_extras);

    int eSignedIDPassCard_len;
    unsigned char *eSignedIDPassCard
       = idpass_api_create_card_with_face(ctx,
                                           &eSignedIDPassCard_len,
                                           bufSurname,
                                           bufGivenName,
                                           bufDateOfBirth,
                                           bufPlaceOfBirth,
                                           bufPin,
                                           reinterpret_cast<char *>(buf),
                                           buf_len,
                                           reinterpret_cast<unsigned char*>(pub_extras_buf),
                                           pub_extras_buf_len,
                                           reinterpret_cast<unsigned char*>(priv_extras_buf),
                                           priv_extras_buf_len);

    if (eSignedIDPassCard != nullptr) {
        ecard = env->NewByteArray(eSignedIDPassCard_len);
        env->SetByteArrayRegion(ecard, 0, eSignedIDPassCard_len, (const jbyte *)eSignedIDPassCard);
        idpass_api_freemem(ctx, eSignedIDPassCard);
    } else {
        ecard = env->NewByteArray(0);
    }

    if (photo) env->ReleaseByteArrayElements(photo, buf, 0);
    if (sur_name) env->ReleaseStringUTFChars(sur_name, bufSurname);
    if (given_name) env->ReleaseStringUTFChars(given_name, bufGivenName);
    if (date_of_birth) env->ReleaseStringUTFChars(date_of_birth, bufDateOfBirth);
    if (place_of_birth) env->ReleaseStringUTFChars(place_of_birth, bufPlaceOfBirth);
    if (pub_extras) env->ReleaseByteArrayElements(pub_extras, pub_extras_buf, 0);
    if (priv_extras) env->ReleaseByteArrayElements(priv_extras, priv_extras_buf, 0);
    if (pin) env->ReleaseStringUTFChars(pin, bufPin);

    return ecard; // encrypted SignedIDPassCard proto object
}

jbyteArray
verify_card_with_face(JNIEnv *env,
                      jobject thiz,
                      jlong context,
                      jbyteArray photo,
                      jbyteArray e_signed_card)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    jbyteArray ret = nullptr;
    jbyte *buf = env->GetByteArrayElements(photo, 0);
    jsize buf_len = env->GetArrayLength(photo);

    jbyte *eSignedIDPassCard = env->GetByteArrayElements(e_signed_card, 0);
    jsize eSignedIDPassCard_len = env->GetArrayLength(e_signed_card);

    int details_len = 0;
    unsigned char *details = idpass_api_verify_card_with_face(
        ctx,
        &details_len,
        reinterpret_cast<unsigned char *>(eSignedIDPassCard),
        eSignedIDPassCard_len,
        reinterpret_cast<char *>(buf),
        buf_len);

    if (details != nullptr) {
        ret = env->NewByteArray(details_len);
        env->SetByteArrayRegion(ret, 0, details_len, (const jbyte *)details);
        idpass_api_freemem(ctx, details);
    } else {
        ret = env->NewByteArray(0);
    }

    env->ReleaseByteArrayElements(photo, buf, 0);
    env->ReleaseByteArrayElements(e_signed_card, eSignedIDPassCard, 0);

    return ret;
}

jbyteArray
verify_card_with_pin(JNIEnv *env,
                     jobject thiz,
                     jlong context,
                     jstring pin,
                     jbyteArray e_signed_card)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    const char *strPin = env->GetStringUTFChars(pin, 0);
    jbyteArray ret = nullptr;

    jbyte *eSignedIDPassCard = env->GetByteArrayElements(e_signed_card, 0);
    jsize eSignedIDPassCard_len = env->GetArrayLength(e_signed_card);

    int details_len = 0;
    unsigned char *details = idpass_api_verify_card_with_pin(
        ctx,
        &details_len,
        reinterpret_cast<unsigned char *>(eSignedIDPassCard),
        eSignedIDPassCard_len,
        strPin);

    if (details != nullptr) {
        ret = env->NewByteArray(details_len);
        env->SetByteArrayRegion(ret, 0, details_len, (const jbyte *)details);
        idpass_api_freemem(ctx, details);
    } else {
        ret = env->NewByteArray(0);
    }

    env->ReleaseStringUTFChars(pin, strPin);
    env->ReleaseByteArrayElements(e_signed_card, eSignedIDPassCard, 0);

    return ret;
}

jbyteArray 
encrypt_with_card(JNIEnv *env,
                 jobject thiz,
                 jlong context,
                 jbyteArray e_signed_card,
                 jbyteArray data)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }
    jbyte *eSignedIDPassCard = env->GetByteArrayElements(e_signed_card, 0);
    jsize eSignedIDPassCard_len = env->GetArrayLength(e_signed_card);

    jbyte *bufData = env->GetByteArrayElements(data, 0);
    jsize bufData_len = env->GetArrayLength(data);
    ///////////////
    int encrypted_len;
    unsigned char *encrypted = idpass_api_encrypt_with_card(
        ctx,
        &encrypted_len,
        reinterpret_cast<unsigned char *>(eSignedIDPassCard),
        eSignedIDPassCard_len,
        reinterpret_cast<unsigned char *>(bufData),
        bufData_len);

    jbyteArray ret = env->NewByteArray(encrypted_len);
    env->SetByteArrayRegion(ret, 0, encrypted_len, (const jbyte *)encrypted);
    idpass_api_freemem(ctx, encrypted);
    ///////////////
    env->ReleaseByteArrayElements(e_signed_card, eSignedIDPassCard, 0);
    env->ReleaseByteArrayElements(data, bufData, 0);

    return ret;
}

jbyteArray 
sign_with_card(JNIEnv *env,
              jobject thiz,
              jlong context,
              jbyteArray e_signed_card,
              jbyteArray data)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }
    jbyte *eSignedIDPassCard = env->GetByteArrayElements(e_signed_card, 0);
    jsize eSignedIDPassCard_len = env->GetArrayLength(e_signed_card);

    jbyte *bufData = env->GetByteArrayElements(data, 0);
    jsize bufData_len = env->GetArrayLength(data);
    ////////////////////////
    int sig_len = 0;
    unsigned char *sig = idpass_api_sign_with_card(
        ctx,
        &sig_len,
        reinterpret_cast<unsigned char *>(eSignedIDPassCard),
        eSignedIDPassCard_len,
        reinterpret_cast<unsigned char *>(bufData),
        bufData_len);

    jbyteArray ret = env->NewByteArray(sig_len);
    env->SetByteArrayRegion(ret, 0, sig_len, (const jbyte *)sig);
    idpass_api_freemem(ctx, sig);
    ////////////////////////
    env->ReleaseByteArrayElements(e_signed_card, eSignedIDPassCard, 0);
    env->ReleaseByteArrayElements(data, bufData, 0);

    return ret;
}

jobject 
generate_qrcode_pixels(JNIEnv *env,
                       jobject thiz,
                       jlong context,
                       jbyteArray data)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }
    auto TestBit = [](unsigned char A[], int k) { // helper function
        return ((A[k / 8] & (1 << (k % 8))) != 0);
    };

    jbyte *buf = env->GetByteArrayElements(data, 0);
    jsize buf_len = env->GetArrayLength(data);

    jclass jcls = env->FindClass("java/util/BitSet"); // careful with BitSet(n)
    jmethodID constructor = env->GetMethodID(jcls, "<init>", "(I)V");

    int square_side_len = 0;

    unsigned char *pixels = idpass_api_qrpixel(
        ctx, reinterpret_cast<unsigned char *>(buf), buf_len, &square_side_len);

    int pixels_count = square_side_len * square_side_len;

    jobject obj
        = env->NewObject(jcls, constructor, pixels_count + 1); // BitSet(n + 1)
    jmethodID setBit = env->GetMethodID(jcls, "set", "(I)V");
    env->CallVoidMethod(obj, setBit, pixels_count);

    // Copy the QR Code pixels into the BitSet object
    for (int i = 0; i < pixels_count; i++) {
        if (TestBit(pixels, i)) {
            env->CallVoidMethod(obj, setBit, i);
        }
    }

    idpass_api_freemem(ctx, pixels);
    env->ReleaseByteArrayElements(data, buf, 0);
    return obj;
}

jbyteArray 
compute_face_128d(JNIEnv *env,
                  jobject thiz,
                  jlong context,
                  jbyteArray photo)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    jbyteArray face128d = nullptr;
    jbyte *buf = env->GetByteArrayElements(photo, 0);
    jsize buf_len = env->GetArrayLength(photo);

    unsigned char facearray[128 * 4];

    int face_count = idpass_api_face128dbuf(
        ctx, reinterpret_cast<char *>(buf), buf_len, facearray);

    // this method only returns workable data if it finds exactly 1 face
    if (face_count == 1) {
        face128d = env->NewByteArray(128 * 4);
        env->SetByteArrayRegion(face128d, 0, 128 * 4, (const jbyte *)facearray);
    } else {
        face128d = env->NewByteArray(0);
    }

    env->ReleaseByteArrayElements(photo, buf, 0);
    return face128d;
}

jbyteArray 
compute_face_64d(JNIEnv *env,
                 jobject thiz,
                 jlong context,
                 jbyteArray photo)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    jbyteArray face64d = nullptr;
    jbyte *buf = env->GetByteArrayElements(photo, 0);
    jsize buf_len = env->GetArrayLength(photo);

    unsigned char facearray[64 * 2];

    int face_count = idpass_api_face64dbuf(
        ctx, reinterpret_cast<char *>(buf), buf_len, facearray);

    // this method only returns workable data if it finds exactly 1 face
    if (face_count == 1) {
        face64d = env->NewByteArray(64 * 2);
        env->SetByteArrayRegion(face64d, 0, 64 * 2, (const jbyte *)facearray);
    } else {
        face64d = env->NewByteArray(0);
    }

    env->ReleaseByteArrayElements(photo, buf, 0);
    return face64d;
}

jbyteArray
decrypt_with_card(JNIEnv *env,
                  jobject thiz,
                  jlong context,
                  jbyteArray ciphertext,
                  jbyteArray skpk)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    jbyte *ciphertext_buf = env->GetByteArrayElements(ciphertext, 0);
    jsize ciphertext_buf_len = env->GetArrayLength(ciphertext);
    jbyte *skpk_buf = env->GetByteArrayElements(skpk, 0);
    jsize skpk_buf_len = env->GetArrayLength(skpk);

    int decrypted_len = 0;
    unsigned char *decrypted = idpass_api_decrypt_with_card(
        ctx,
        &decrypted_len,
        reinterpret_cast<unsigned char *>(ciphertext_buf),
        ciphertext_buf_len,
        reinterpret_cast<unsigned char *>(skpk_buf),
        skpk_buf_len);

    if (!decrypted) {
        env->ReleaseByteArrayElements(ciphertext, ciphertext_buf, 0);
        env->ReleaseByteArrayElements(skpk, skpk_buf, 0);
        return env->NewByteArray(0);
    }

    jbyteArray plaintext = env->NewByteArray(decrypted_len);
    env->SetByteArrayRegion(plaintext, 0, decrypted_len, (const jbyte *)decrypted);
    idpass_api_freemem(ctx, decrypted);

    env->ReleaseByteArrayElements(ciphertext, ciphertext_buf, 0);
    env->ReleaseByteArrayElements(skpk, skpk_buf, 0);

    return plaintext;
}

jbyteArray
generate_encryption_key(JNIEnv *env, jclass clazz)
{
    unsigned char buf[ENCRYPTION_KEY_LEN];
    idpass_api_generate_encryption_key(buf, sizeof buf);
    jbyteArray key = env->NewByteArray(ENCRYPTION_KEY_LEN);
    env->SetByteArrayRegion(
        key, 0, ENCRYPTION_KEY_LEN, (const jbyte *)buf);

    return key;
}

jbyteArray
generate_secret_signature_key(JNIEnv *env, jclass clazz)
{
    unsigned char buf[SECRET_SIGNATURE_KEY_LEN];
    idpass_api_generate_secret_signature_key(buf, sizeof buf);
    jbyteArray key = env->NewByteArray(SECRET_SIGNATURE_KEY_LEN);
    env->SetByteArrayRegion(
        key, 0, SECRET_SIGNATURE_KEY_LEN, (const jbyte *)buf);

    return key;
}

jbyteArray
card_decrypt(JNIEnv *env, jobject thiz, jlong context,
    jbyteArray ecard, jbyteArray key)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    jbyte *ecard_buf = env->GetByteArrayElements(ecard, 0);
    jsize ecard_buf_len = env->GetArrayLength(ecard);
    jbyte *key_buf = env->GetByteArrayElements(key, 0);
    jsize key_buf_len = env->GetArrayLength(key);

    int len = ecard_buf_len;

    if (idpass_api_card_decrypt(ctx,
        reinterpret_cast<unsigned char*>(ecard_buf), &len,
        reinterpret_cast<unsigned char *>(key_buf), key_buf_len)
    != 0) {
        env->ReleaseByteArrayElements(ecard, ecard_buf, 0);
        env->ReleaseByteArrayElements(key, key_buf, 0);
        return env->NewByteArray(0);
    }

    jbyteArray plaintext = env->NewByteArray(len);
    env->SetByteArrayRegion(plaintext, 0, len, ecard_buf);

    env->ReleaseByteArrayElements(ecard, ecard_buf, 0);
    env->ReleaseByteArrayElements(key, key_buf, 0);

    return plaintext;
}

jboolean
verify_with_card(JNIEnv *env,
                 jobject thiz,
                 jlong context,
                 jbyteArray msg,
                 jbyteArray signature,
                 jbyteArray pubkey)
{
    void *ctx = reinterpret_cast<void *>(context);
    jboolean flag = JNI_FALSE;

    if (!ctx) {
        LOGI("null ctx");
        return flag;
    }

    jbyte *msg_buf = env->GetByteArrayElements(msg, 0);
    jsize msg_buf_len = env->GetArrayLength(msg);

    jbyte *signature_buf = env->GetByteArrayElements(signature, 0);
    jsize signature_buf_len = env->GetArrayLength(signature);

    jbyte *pubkey_buf = env->GetByteArrayElements(pubkey, 0);
    jsize pubkey_buf_len = env->GetArrayLength(pubkey);

    if (idpass_api_verify_with_card(
            ctx,
            reinterpret_cast<unsigned char *>(msg_buf),
            msg_buf_len,
            reinterpret_cast<unsigned char *>(signature_buf),
            signature_buf_len,
            reinterpret_cast<unsigned char *>(pubkey_buf),
            pubkey_buf_len)
    == 0) {
        flag = JNI_TRUE;
    }

    env->ReleaseByteArrayElements(msg, msg_buf, 0);
    env->ReleaseByteArrayElements(signature, signature_buf, 0);
    env->ReleaseByteArrayElements(pubkey, pubkey_buf, 0);

    return flag;
}

jfloat
compare_face_template(JNIEnv *env,
                      jclass clazz,
                      jbyteArray face1,
                      jbyteArray face2)
{
    jbyte *face1_buf = env->GetByteArrayElements(face1, 0);
    jsize face1_buf_len = env->GetArrayLength(face1);
    jbyte *face2_buf = env->GetByteArrayElements(face2, 0);
    jsize face2_buf_len = env->GetArrayLength(face2);

    float result = -10.0;

    int status = idpass_api_compare_face_template(
        reinterpret_cast<unsigned char *>(face1_buf),
        face1_buf_len,
        reinterpret_cast<unsigned char *>(face2_buf),
        face2_buf_len,
        &result);

    if (status == 0) {
        return result;
    }

    env->ReleaseByteArrayElements(face1, face1_buf, 0);
    env->ReleaseByteArrayElements(face2, face2_buf, 0);

    return result;
}

/* This API method is for quick test only to probe protobuf compatibility */
jbyteArray protobufTest(JNIEnv *env,
                        jobject thiz,
                        jlong context,
                        jstring surname,
                        jstring given_name,
                        jstring date_of_birth,
                        jstring place_of_birth,
                        jstring extras)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }
    const char *s_surname = env->GetStringUTFChars(surname, 0);
    const char *s_given_name = env->GetStringUTFChars(given_name, 0);
    const char *s_dob = env->GetStringUTFChars(date_of_birth, 0);
    const char *s_pob = env->GetStringUTFChars(place_of_birth, 0);
    const char *s_extras = env->GetStringUTFChars(extras, 0);

    int len;
    unsigned char *buf = protobuf_test(
        ctx, &len, s_surname, s_given_name, s_dob, s_pob, s_extras);

    env->ReleaseStringUTFChars(surname, s_surname);
    env->ReleaseStringUTFChars(given_name, s_given_name);
    env->ReleaseStringUTFChars(date_of_birth, s_dob);
    env->ReleaseStringUTFChars(place_of_birth, s_pob);
    env->ReleaseStringUTFChars(extras, s_extras);

    jbyteArray ret = env->NewByteArray(len);
    env->SetByteArrayRegion(ret, 0, len, (const jbyte *)buf);

    return ret;
}

void
testfunc(JNIEnv *env, jobject thiz, jlong context, jbyteArray data, jstring str)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return;
    }

    jbyte *buf = env->GetByteArrayElements(data, 0);
    jsize buf_len = env->GetArrayLength(data);
    const char *bufStr = env->GetStringUTFChars(str, 0);

    LOGI("testfunc");

    env->ReleaseByteArrayElements(data, buf, 0);
    env->ReleaseStringUTFChars(str, bufStr);
}

jbyteArray
generate_root_certificate(JNIEnv *env, jclass clazz, jbyteArray secretKey)
{
    jbyte *secretKey_buf = env->GetByteArrayElements(secretKey, 0);
    jsize secretKey_buf_len = env->GetArrayLength(secretKey);

    unsigned char buf[128];
    jbyteArray rootCertificate = env->NewByteArray(0);

    if (idpass_api_generate_root_certificate(
            reinterpret_cast<unsigned char *>(secretKey_buf),
            secretKey_buf_len,
            buf,
            sizeof buf)
    == 0) {
        rootCertificate = env->NewByteArray(sizeof buf);
        env->SetByteArrayRegion(rootCertificate, 0, sizeof buf, (const jbyte*)buf);
    }

    env->ReleaseByteArrayElements(secretKey, secretKey_buf, 0);
    return rootCertificate;
}

jbyteArray
generate_child_certificate(JNIEnv *env, jclass clazz,
    jbyteArray parentSecretKey, jbyteArray childSecretKey)
{
    jbyte *parentSecretKey_buf = env->GetByteArrayElements(parentSecretKey, 0);
    jsize parentSecretKey_buf_len = env->GetArrayLength(parentSecretKey);
    jbyte *childSecretKey_buf = env->GetByteArrayElements(childSecretKey, 0);
    jsize childSecretKey_buf_len = env->GetArrayLength(childSecretKey);

    unsigned char buf[128];
    jbyteArray childCertificate = env->NewByteArray(0);

    if (idpass_api_generate_child_certificate(
            reinterpret_cast<unsigned char *>(parentSecretKey_buf),
            parentSecretKey_buf_len,
            reinterpret_cast<unsigned char *>(childSecretKey_buf),
            childSecretKey_buf_len,
            buf,
            sizeof buf)
    == 0) {
        childCertificate = env->NewByteArray(sizeof buf);
        env->SetByteArrayRegion(childCertificate, 0, sizeof buf, (const jbyte*)buf);
    }

    env->ReleaseByteArrayElements(parentSecretKey, parentSecretKey_buf, 0);
    env->ReleaseByteArrayElements(childSecretKey, childSecretKey_buf, 0);
    return childCertificate;
}

void
add_revoked_key(JNIEnv *env, jclass clazz, jbyteArray pubkey)
{
    jbyte *pubkey_buf = env->GetByteArrayElements(pubkey, 0);
    jsize pubkey_buf_len = env->GetArrayLength(pubkey);
    idpass_api_add_revoked_key(reinterpret_cast<unsigned char*>(pubkey_buf), pubkey_buf_len);
    env->ReleaseByteArrayElements(pubkey, pubkey_buf, 0);
}

jboolean
add_certificates(JNIEnv *env,
                 jobject thiz,
                 jlong context,
                 jobjectArray certificates)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx || !certificates) {
        return JNI_FALSE;
    }

    int count = env->GetArrayLength(certificates);

    jbyteArray jba;
    jbyte *buf;
    int buf_len;

    unsigned char **cert;
    cert = new unsigned char *[count];
    int *nlen = new int[count];

    for (int i = 0; i < count; i++) {
        jba = (jbyteArray)env->GetObjectArrayElement(certificates, i);
        buf = env->GetByteArrayElements(jba, 0);
        buf_len = env->GetArrayLength(jba);
        nlen[i] = buf_len;
        cert[i] = new unsigned char[buf_len];
        std::memcpy(cert[i], buf, buf_len);
        env->ReleaseByteArrayElements(jba, buf, JNI_ABORT);
        env->DeleteLocalRef(jba);
    }

    // returns 0 if every certificate validates
    int status = idpass_api_add_certificates(ctx, cert, nlen, count);

    for (int i = 0; i < count; i++) {
        delete[] cert[i];
    }

    delete[] cert;
    delete[] nlen;

    return status == 0 ? JNI_TRUE : JNI_FALSE;
}

JNINativeMethod IDPASS_JNI[] = {
    {(char *)"ioctl",
     (char *)"(J[B)[B",
     (void *)ioctl},

    {(char *)"idpass_init",
     (char *)"([B[B[B[[B)J",
     (void *)idpass_init},

    {(char *)"create_card_with_face",
     (char *)"(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[B[B[B)[B",
     (void *)create_card_with_face},

    {(char *)"verify_card_with_face",
     (char *)"(J[B[B)[B",
     (void *)verify_card_with_face},

    {(char *)"verify_card_with_pin",
     (char *)"(JLjava/lang/String;[B)[B",
     (void *)verify_card_with_pin},

    {(char *)"encrypt_with_card",
     (char *)"(J[B[B)[B",
     (void *)encrypt_with_card},

    {(char *)"sign_with_card",
     (char *)"(J[B[B)[B",
     (void *)sign_with_card},

    {(char *)"generate_qrcode_pixels",
     (char *)"(J[B)Ljava/util/BitSet;",
     (void *)generate_qrcode_pixels},

    {(char *)"compute_face_128d",
     (char *)"(J[B)[B",
     (void *)compute_face_128d},

    {(char *)"compute_face_64d",
     (char *)"(J[B)[B",
     (void *)compute_face_64d},

    {(char *)"generate_encryption_key",
     (char *)"()[B",
     (void *)generate_encryption_key},

    {(char *)"generate_secret_signature_key",
     (char *)"()[B",
     (void *)generate_secret_signature_key},

    {(char *)"card_decrypt",
     (char *)"(J[B[B)[B",
     (void *)card_decrypt},

    {(char *)"decrypt_with_card",
     (char *)"(J[B[B)[B",
     (void *)decrypt_with_card},

    {(char *)"verify_with_card",
     (char *)"(J[B[B[B)Z",
     (void *)verify_with_card},

    {(char *)"compare_face_template",
     (char *)"([B[B)F",
     (void *)compare_face_template},

    {(char *)"generate_root_certificate",
     (char *)"([B)[B",
     (void *)generate_root_certificate},

    {(char *)"generate_child_certificate",
     (char *)"([B[B)[B",
     (void *)generate_child_certificate},

    {(char *)"add_revoked_key",
     (char *)"([B)V",
     (void *)add_revoked_key},

    {(char *)"add_certificates",
     (char *)"(J[[B)Z",
     (void *)add_certificates},

};

int IDPASS_JNI_TLEN = sizeof IDPASS_JNI / sizeof IDPASS_JNI[0];
