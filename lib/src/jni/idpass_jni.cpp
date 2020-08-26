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

#include "../idpass.h"

#include <cstring>
#include <iostream>
#include <jni.h>
#include <list>
#include <string>
#include <vector>

#ifdef ANDROID
#include <android/log.h>

#define LOGI(...)               \
    ((void)__android_log_print( \
        ANDROID_LOG_INFO, "idpass_jni::C++", __VA_ARGS__))
#else
#define LOGI(...)
#endif

jlong idpass_init(JNIEnv *env,
                  jclass clazz,
                  jbyteArray cryptokeys,
                  jbyteArray rootcerts)
{
    jbyte *cryptokeys_buf = env->GetByteArrayElements(cryptokeys, 0);
    jsize cryptokeys_buf_len = env->GetArrayLength(cryptokeys);

    jbyte *rootcerts_buf = rootcerts != nullptr ? env->GetByteArrayElements(rootcerts, 0) : nullptr;
    jsize rootcerts_buf_len = rootcerts != nullptr ? env->GetArrayLength(rootcerts) : 0;

    void *ctx
        = idpass_lite_init(reinterpret_cast<unsigned char *>(cryptokeys_buf),
                           cryptokeys_buf_len,
                           reinterpret_cast<unsigned char *>(rootcerts_buf),
                           rootcerts_buf_len);

    env->ReleaseByteArrayElements(cryptokeys, cryptokeys_buf, 0);
    if (rootcerts) {
        env->ReleaseByteArrayElements(rootcerts, rootcerts_buf, 0);
    }

    if (ctx) {
        LOGI("idpass_api_init ok");
        return reinterpret_cast<long>(ctx); // no error
    } else {
        LOGI("idpass_api_init fail: sodium_init");
        return 0;
    }
}

jboolean generate_encryption_key(JNIEnv *env, jclass clazz, jbyteArray enc)
{
    jbyte* enc_buf = env->GetByteArrayElements(enc, 0);
    jsize enc_buf_len = env->GetArrayLength(enc);

    unsigned char buf[ENCRYPTION_KEY_LEN];
    int status = idpass_lite_generate_encryption_key(
        reinterpret_cast<unsigned char*>(enc_buf), enc_buf_len);

    env->ReleaseByteArrayElements(enc, enc_buf, 0);
    return status == 0 ? JNI_TRUE : JNI_FALSE;
}

jboolean generate_secret_signature_keypair(JNIEnv *env, jclass clazz,
    jbyteArray pk, jbyteArray sk)
{
    jbyte* pk_buf = env->GetByteArrayElements(pk, 0);
    jsize pk_buf_len = env->GetArrayLength(pk);

    jbyte* sk_buf = env->GetByteArrayElements(sk, 0);
    jsize sk_buf_len = env->GetArrayLength(sk);

    int status = idpass_lite_generate_secret_signature_keypair(
        reinterpret_cast<unsigned char*>(pk_buf), pk_buf_len,
        reinterpret_cast<unsigned char*>(sk_buf), sk_buf_len);

    env->ReleaseByteArrayElements(pk, pk_buf, 0);
    env->ReleaseByteArrayElements(sk, sk_buf, 0);

    return status == 0 ? JNI_TRUE : JNI_FALSE;
}

jfloat compare_face_template(JNIEnv *env,
                             jclass clazz,
                             jbyteArray face1,
                             jbyteArray face2)
{
    jbyte *face1_buf = env->GetByteArrayElements(face1, 0);
    jsize face1_buf_len = env->GetArrayLength(face1);
    jbyte *face2_buf = env->GetByteArrayElements(face2, 0);
    jsize face2_buf_len = env->GetArrayLength(face2);

    float result = -10.0;

    int status = idpass_lite_compare_face_template(
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

jbyteArray
generate_root_certificate(JNIEnv *env, jclass clazz, jbyteArray secretKey)
{
    jbyte *secretKey_buf = env->GetByteArrayElements(secretKey, 0);
    jsize secretKey_buf_len = env->GetArrayLength(secretKey);

    jbyteArray rootCertificate = env->NewByteArray(0);

    int outlen = 0;
    unsigned char *rootcert = idpass_lite_generate_root_certificate(
        reinterpret_cast<unsigned char *>(secretKey_buf),
        secretKey_buf_len,
        &outlen);
    if (rootcert) {
        rootCertificate = env->NewByteArray(outlen);
        env->SetByteArrayRegion(
            rootCertificate, 0, outlen, (const jbyte *)rootcert);
    }

    env->ReleaseByteArrayElements(secretKey, secretKey_buf, 0);
    return rootCertificate;
}

jbyteArray generate_child_certificate(JNIEnv *env,
                                      jclass clazz,
                                      jbyteArray parentSecretKey,
                                      jbyteArray childSecretKey)
{
    jbyte *parentSecretKey_buf = env->GetByteArrayElements(parentSecretKey, 0);
    jsize parentSecretKey_buf_len = env->GetArrayLength(parentSecretKey);
    jbyte *childSecretKey_buf = env->GetByteArrayElements(childSecretKey, 0);
    jsize childSecretKey_buf_len = env->GetArrayLength(childSecretKey);

    jbyteArray childCertificate = env->NewByteArray(0);

    int outlen = 0;
    unsigned char *childcert = idpass_lite_generate_child_certificate(
        reinterpret_cast<unsigned char *>(parentSecretKey_buf),
        parentSecretKey_buf_len,
        reinterpret_cast<unsigned char *>(childSecretKey_buf),
        childSecretKey_buf_len,
        &outlen);

    if (childcert) {
        childCertificate = env->NewByteArray(outlen);
        env->SetByteArrayRegion(
            childCertificate, 0, outlen, (const jbyte *)childcert);
    }

    env->ReleaseByteArrayElements(parentSecretKey, parentSecretKey_buf, 0);
    env->ReleaseByteArrayElements(childSecretKey, childSecretKey_buf, 0);
    return childCertificate;
}

void add_revoked_key(JNIEnv *env, jclass clazz, jbyteArray pubkey)
{
    jbyte *pubkey_buf = env->GetByteArrayElements(pubkey, 0);
    jsize pubkey_buf_len = env->GetArrayLength(pubkey);
    idpass_lite_add_revoked_key(reinterpret_cast<unsigned char *>(pubkey_buf),
                                pubkey_buf_len);
    env->ReleaseByteArrayElements(pubkey, pubkey_buf, 0);
}

jbyteArray ioctl(JNIEnv *env, jobject thiz, jlong context, jbyteArray iobuf)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    jbyte *buf = env->GetByteArrayElements(iobuf, 0);
    jsize buf_len = env->GetArrayLength(iobuf);

    idpass_lite_ioctl(
        ctx, nullptr, reinterpret_cast<unsigned char *>(buf), buf_len);

    env->ReleaseByteArrayElements(iobuf, buf, 0);
    return env->NewByteArray(0);
}

jbyteArray create_card_with_face(JNIEnv *env,
                                 jobject thiz,
                                 jlong context,
                                 jbyteArray ident)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    jbyteArray ecard = nullptr;

    jbyte *ident_buf = env->GetByteArrayElements(ident, 0);
    jsize ident_buf_len = env->GetArrayLength(ident);

    int outlen;
    unsigned char *eSignedIDPassCard = idpass_lite_create_card_with_face(
        ctx,
        &outlen,
        reinterpret_cast<unsigned char *>(ident_buf),
        ident_buf_len);

    if (eSignedIDPassCard != nullptr) {
        ecard = env->NewByteArray(outlen);
        env->SetByteArrayRegion(
            ecard, 0, outlen, (const jbyte *)eSignedIDPassCard);
        idpass_lite_freemem(ctx, eSignedIDPassCard);
    } else {
        ecard = env->NewByteArray(0);
    }

    if (ident_buf)
        env->ReleaseByteArrayElements(ident, ident_buf, 0);

    return ecard; // encrypted SignedIDPassCard proto object
}

jbyteArray verify_card_with_face(JNIEnv *env,
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
    unsigned char *details = idpass_lite_verify_card_with_face(
        ctx,
        &details_len,
        reinterpret_cast<unsigned char *>(eSignedIDPassCard),
        eSignedIDPassCard_len,
        reinterpret_cast<char *>(buf),
        buf_len);

    if (details != nullptr) {
        ret = env->NewByteArray(details_len);
        env->SetByteArrayRegion(ret, 0, details_len, (const jbyte *)details);
        idpass_lite_freemem(ctx, details);
    } else {
        ret = env->NewByteArray(0);
    }

    env->ReleaseByteArrayElements(photo, buf, 0);
    env->ReleaseByteArrayElements(e_signed_card, eSignedIDPassCard, 0);

    return ret;
}

jbyteArray verify_card_with_pin(JNIEnv *env,
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
    unsigned char *details = idpass_lite_verify_card_with_pin(
        ctx,
        &details_len,
        reinterpret_cast<unsigned char *>(eSignedIDPassCard),
        eSignedIDPassCard_len,
        strPin);

    if (details != nullptr) {
        ret = env->NewByteArray(details_len);
        env->SetByteArrayRegion(ret, 0, details_len, (const jbyte *)details);
        idpass_lite_freemem(ctx, details);
    } else {
        ret = env->NewByteArray(0);
    }

    env->ReleaseStringUTFChars(pin, strPin);
    env->ReleaseByteArrayElements(e_signed_card, eSignedIDPassCard, 0);

    return ret;
}

jbyteArray encrypt_with_card(JNIEnv *env,
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
    unsigned char *encrypted = idpass_lite_encrypt_with_card(
        ctx,
        &encrypted_len,
        reinterpret_cast<unsigned char *>(eSignedIDPassCard),
        eSignedIDPassCard_len,
        reinterpret_cast<unsigned char *>(bufData),
        bufData_len);

    jbyteArray ret = env->NewByteArray(encrypted_len);
    env->SetByteArrayRegion(ret, 0, encrypted_len, (const jbyte *)encrypted);
    idpass_lite_freemem(ctx, encrypted);
    ///////////////
    env->ReleaseByteArrayElements(e_signed_card, eSignedIDPassCard, 0);
    env->ReleaseByteArrayElements(data, bufData, 0);

    return ret;
}

jbyteArray sign_with_card(JNIEnv *env,
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
    unsigned char sig[64];
    int sig_len = 64;
    if (0 != idpass_lite_sign_with_card(
        ctx, sig, 64,
        reinterpret_cast<unsigned char *>(eSignedIDPassCard),
        eSignedIDPassCard_len,
        reinterpret_cast<unsigned char *>(bufData),
        bufData_len)) 
    {
        env->ReleaseByteArrayElements(e_signed_card, eSignedIDPassCard, 0);
        env->ReleaseByteArrayElements(data, bufData, 0);
        return env->NewByteArray(0);
    }

    jbyteArray ret = env->NewByteArray(sig_len);
    env->SetByteArrayRegion(ret, 0, sig_len, (const jbyte *)sig);
    //idpass_lite_freemem(ctx, sig);
    ////////////////////////
    env->ReleaseByteArrayElements(e_signed_card, eSignedIDPassCard, 0);
    env->ReleaseByteArrayElements(data, bufData, 0);

    return ret;
}

jobject generate_qrcode_pixels(JNIEnv *env,
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

    unsigned char *pixels = idpass_lite_qrpixel(
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

    idpass_lite_freemem(ctx, pixels);
    env->ReleaseByteArrayElements(data, buf, 0);
    return obj;
}

jbyteArray
compute_face_128d(JNIEnv *env, jobject thiz, jlong context, jbyteArray photo)
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

    int face_count = idpass_lite_face128dbuf(
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
compute_face_64d(JNIEnv *env, jobject thiz, jlong context, jbyteArray photo)
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

    int face_count = idpass_lite_face64dbuf(
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

jbyteArray decrypt_with_card(JNIEnv *env,
                             jobject thiz,
                             jlong context,
                             jbyteArray fullcard,
                             jbyteArray encrypted)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    jbyte *fullcard_buf = env->GetByteArrayElements(fullcard, 0);
    jsize fullcard_buf_len = env->GetArrayLength(fullcard);
    jbyte *encrypted_buf = env->GetByteArrayElements(encrypted, 0);
    jsize encrypted_buf_len = env->GetArrayLength(encrypted);

    int decrypted_len = 0;
    unsigned char *decrypted = idpass_lite_decrypt_with_card(
        ctx,
        &decrypted_len,
        reinterpret_cast<unsigned char *>(fullcard_buf),
        fullcard_buf_len,
        reinterpret_cast<unsigned char *>(encrypted_buf),
        encrypted_buf_len);

    if (!decrypted) {
        env->ReleaseByteArrayElements(fullcard, fullcard_buf, 0);
        env->ReleaseByteArrayElements(encrypted, encrypted_buf, 0);
        return env->NewByteArray(0);
    }

    jbyteArray plaintext = env->NewByteArray(decrypted_len);
    env->SetByteArrayRegion(
        plaintext, 0, decrypted_len, (const jbyte *)decrypted);
    idpass_lite_freemem(ctx, decrypted);

    env->ReleaseByteArrayElements(fullcard, fullcard_buf, 0);
    env->ReleaseByteArrayElements(encrypted, encrypted_buf, 0);

    return plaintext;
}

jbyteArray card_decrypt(JNIEnv *env,
                        jobject thiz,
                        jlong context,
                        jbyteArray ecard,
                        jbyteArray key)
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

    if (idpass_lite_card_decrypt(ctx,
                                 reinterpret_cast<unsigned char *>(ecard_buf),
                                 &len,
                                 reinterpret_cast<unsigned char *>(key_buf),
                                 key_buf_len)
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

jboolean verify_with_card(JNIEnv *env,
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

    if (idpass_lite_verify_with_card(
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

jboolean add_certificates(JNIEnv *env,
                          jobject thiz,
                          jlong context,
                          jbyteArray certificates)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx || !certificates) {
        return JNI_FALSE;
    }

    jboolean flag = false;
    jbyte *certificates_buf = env->GetByteArrayElements(certificates, 0);
    jsize certificates_buf_len = env->GetArrayLength(certificates);

    if (0
        == idpass_lite_add_certificates(
            ctx,
            reinterpret_cast<unsigned char *>(certificates_buf),
            certificates_buf_len)) {
        flag = true;
    }

    env->ReleaseByteArrayElements(certificates, certificates_buf, 0);

    return flag;
}

jint verify_card_certificate(JNIEnv *env,
                             jobject thiz,
                             jlong context,
                             jbyteArray fullcard)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx || !fullcard) {
        return -1;
    }

    jbyte *fullcard_buf = env->GetByteArrayElements(fullcard, 0);
    jsize fullcard_buf_len = env->GetArrayLength(fullcard);

    int status = idpass_lite_verify_certificate(
        ctx, reinterpret_cast<unsigned char *>(fullcard_buf), fullcard_buf_len);

    env->ReleaseByteArrayElements(fullcard, fullcard_buf, 0);

    return status;
}

jbyteArray uio(JNIEnv *env, jobject thiz, jlong context, jint typ)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        LOGI("null ctx");
        return env->NewByteArray(0);
    }

    jbyteArray ecard = nullptr;

    unsigned char *buf = idpass_lite_uio(ctx, typ);
    int buf_len = 0;

    if (buf != nullptr) {
        std::memcpy(&buf_len, buf, sizeof(int));
        ecard = env->NewByteArray(buf_len);
        env->SetByteArrayRegion(
            ecard, 0, buf_len, (const jbyte *)(buf + sizeof(int)));
        idpass_lite_freemem(ctx, buf);
    } else {
        ecard = env->NewByteArray(0);
    }

    return ecard; 
}

jboolean verify_card_signature(JNIEnv *env,
                               jobject thiz,
                               jlong context,
                               jbyteArray fullcard)
{
    void *ctx = reinterpret_cast<void *>(context);
    if (!ctx) {
        return JNI_FALSE;
    }

    jbyte *fullcard_buf = env->GetByteArrayElements(fullcard, 0);
    jsize fullcard_buf_len = env->GetArrayLength(fullcard);

    if (0
        != idpass_lite_verify_card_signature(
            ctx, (unsigned char*)fullcard_buf, fullcard_buf_len)) {
        return JNI_FALSE;
    }

    env->ReleaseByteArrayElements(fullcard, fullcard_buf, 0);
    return JNI_TRUE;
}

JNINativeMethod IDPASS_JNI[] = {
    {(char *)"ioctl", (char *)"(J[B)[B", (void *)ioctl},

    {(char *)"idpass_init", (char *)"([B[B)J", (void *)idpass_init},

    {(char *)"create_card_with_face",
     (char *)"(J[B)[B",
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

    {(char *)"sign_with_card", (char *)"(J[B[B)[B", (void *)sign_with_card},

    {(char *)"generate_qrcode_pixels",
     (char *)"(J[B)Ljava/util/BitSet;",
     (void *)generate_qrcode_pixels},

    {(char *)"compute_face_128d", (char *)"(J[B)[B", (void *)compute_face_128d},

    {(char *)"compute_face_64d", (char *)"(J[B)[B", (void *)compute_face_64d},

    {(char *)"generate_encryption_key",
     (char *)"([B)Z",
     (void *)generate_encryption_key},

    {(char *)"generate_secret_signature_keypair",
     (char *)"([B[B)Z",
     (void *)generate_secret_signature_keypair},

    {(char *)"card_decrypt", (char *)"(J[B[B)[B", (void *)card_decrypt},

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

    {(char *)"add_revoked_key", (char *)"([B)V", (void *)add_revoked_key},

    {(char *)"add_certificates", (char *)"(J[B)Z", (void *)add_certificates},

    {(char *)"verify_card_certificate",
     (char *)"(J[B)I",
     (void *)verify_card_certificate},

    {(char *)"verify_card_signature",
     (char *)"(J[B)Z",
     (void *)verify_card_signature},
};

int IDPASS_JNI_TLEN = sizeof IDPASS_JNI / sizeof IDPASS_JNI[0];
