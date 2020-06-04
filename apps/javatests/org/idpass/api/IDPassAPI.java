package org.idpass.api;

import at.favre.lib.bytes.Bytes;
import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.interfaces.AEAD;
import com.goterl.lazycode.lazysodium.interfaces.Box;
import com.goterl.lazycode.lazysodium.interfaces.SecretBox;
import com.goterl.lazycode.lazysodium.interfaces.Sign;
import com.goterl.lazycode.lazysodium.utils.Key;
import com.goterl.lazycode.lazysodium.utils.KeyPair;
import com.goterl.lazycode.lazysodium.utils.LibraryLoader;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.*;
import javax.imageio.ImageIO;

public class IDPassAPI {
  private static long ctx;
  public static LazySodiumJava lazySodium;

  static {
    System.loadLibrary("entrypoint");

    lazySodium =
        new LazySodiumJava(new SodiumJava(LibraryLoader.Mode.BUNDLED_ONLY));
  }

  ////////////////////// start of JNI ////////////////////////////////////////
  public native long idpassInit(byte[] enc, byte[] sig, byte[] verif,
                                int count);

  public native byte[] idpassCreateCardWithFace(
      long ctx, String surName, String givenName, String dateOfBirth,
      String placeOfBirth, String extras, String pin, byte[] photo);

  public native byte[] idpassVerifyCardWithFace(long ctx, byte[] photo,
                                                byte[] eSignedCard);

  public native byte[] idpassVerifyCardWithPin(long ctx, String pin,
                                               byte[] eSignedCard);

  public native byte[] idpassComputeFace128D(long ctx, byte[] photo);

  public native byte[] idpassComputeFace64D(long ctx, byte[] photo);

  public native byte[] idpassEncryptWithCard(long ctx, byte[] eSignedCard,
                                             byte[] data);

  public native byte[] idpassSignWithCard(long ctx, byte[] eSignedCard,
                                          byte[] data);

  public native BitSet idpassqrpixels(long ctx, byte[] data);
  //////////////////////// end of JNI ////////////////////////////////////////

  private static byte[] decodeQRCode(File qrCodeimage) throws IOException {
    BufferedImage bufferedImage = ImageIO.read(qrCodeimage);
    LuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
    BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));

    byte[] content = new byte[0];

    try {
      Result result = new MultiFormatReader().decode(bitmap);
      Map m = result.getResultMetadata();

      if (m.containsKey(ResultMetadataType.BYTE_SEGMENTS)) {
        List L = (List)m.get(ResultMetadataType.BYTE_SEGMENTS);
        content = (byte[])L.get(0);
      } else {
        content = result.getText().getBytes();
      }

    } catch (NotFoundException e) {
      System.out.println("no QR Code in the image");
    }

    return content;
  }

  public long idpassInit() {
    byte[] encryption_key = new byte[AEAD.CHACHA20POLY1305_IETF_KEYBYTES]; // 32
    byte[] signature_pk = new byte[Sign.PUBLICKEYBYTES];                   // 32
    byte[] signature_sk = new byte[Sign.BYTES];                            // 64
    byte[] verification_pk = new byte[Sign.PUBLICKEYBYTES];                // 32
    byte[] verification_sk = new byte[Sign.BYTES];                         // 64

    lazySodium.cryptoAeadChaCha20Poly1305IetfKeygen(encryption_key);
    lazySodium.cryptoSignKeypair(signature_pk, signature_sk);
    lazySodium.cryptoSignKeypair(verification_pk, verification_sk);

    ctx = idpassInit(encryption_key, signature_sk, verification_pk, 1);
    return ctx;
  }

  public static void main(String args[]) throws IOException {
    if (args.length != 2) {
      System.out.println("Please specify qr code image and data");
      System.exit(1);
    }
    File file1 = new File(args[0]);

    int len = 0;

    byte[] ecard = decodeQRCode(file1);

    File file2 = new File(args[1]);
    FileInputStream qrcode_dat = new FileInputStream(file2);
    byte[] ecard_buff = new byte[(int)file2.length()];

    qrcode_dat.read(ecard_buff);

    if (Arrays.equals(ecard, ecard_buff) == true) {
      System.out.println("QR Code decoding match");
    } else {
      System.out.println("-- QR Code decoding mismatch ---");
      System.exit(3);
    }

    IDPassAPI obj = new IDPassAPI();
    if (obj.idpassInit() == 0) {
      System.out.println("** init fail **");
      System.exit(2);
    }

    System.out.println("");
  }
}
