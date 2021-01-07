/*
 * Copyright (C) 2020 Newlogic Pte. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 *
 */

package org.idpass.lite;

import java.util.BitSet;

/**
 * Wrapper class of the libidpasslite.so shared
 * library.
 */

public class IDPassReader {

    static {
        String idpasslib = System.getenv("IDPASSLITE");
        if (idpasslib == null) {
            System.out.println("Cannot find libidpasslite.so");
            System.exit(1);
        }
        System.load(idpasslib);
    }

    //========================== JNI section =============================
    private native long idpass_init(byte[] ks, byte[] rootcerts);
    private native byte[] ioctl(long ctx, byte[] cmd);

    private native byte[] create_card_with_face(
            long ctx,
            byte[] ident);

    private native byte[] verify_card_with_face(long ctx, byte[] photo, byte[] ecard);
    private native byte[] verify_card_with_pin(long ctx, String pin, byte[] ecard);
    private native byte[] encrypt_with_card(long ctx, byte[] ecard, byte[] data);
    private native byte[] decrypt_with_card(long ctx, byte[] ciphertext, byte[] skpk);
    private native byte[] sign_with_card(long ctx, byte[] ecard, byte[] data);
    private native boolean verify_with_card(long ctx, byte[] msg, byte[] signature, byte[] pubkey);
    private native BitSet generate_qrcode_pixels(long ctx, byte[] data);
    private native byte[] compute_face_128d(long ctx, byte[] photo);
    private native byte[] compute_face_64d(long ctx, byte[] photo);
    private static native boolean generate_encryption_key(byte[] enc); // 32
    private static native boolean generate_secret_signature_keypair(byte[] pk, byte[] sk); // 64
    private native byte[] card_decrypt(long ctx, byte[] ecard, byte[] key);
    private native float compare_face_template(byte[] face1, byte[] face2);
    private static native byte[] generate_root_certificate(byte[] secretKey);
    private static native byte[] generate_child_certificate(byte[] parentSecretKey, byte[] childSecretKey);
    private static native void add_revoked_key(byte[] pubkey);
    private native boolean add_certificates(long ctx, byte[] intermedcerts);
    private native int verify_card_certificate(long ctx, byte[] blob);
    private native boolean verify_card_signature(long ctx, byte[] blob);
    private static native byte[] merge_CardDetails(byte[] d1, byte[] d2);
    //=========================================================

    public static void main(String args[])
    {
        System.out.println("JNI methods/libidpasslite.so linking OK");
    }
}
