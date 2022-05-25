import IDPassLite

if __name__ == "__main__":
    encryptionKey   = IDPassLite.Helper.generate_encryption_key()
    signatureKey    = IDPassLite.Helper.generate_secret_signature_key()
    verificationKey = IDPassLite.Helper.getPublicKey(signatureKey)

    reader = IDPassLite.Reader(encryptionKey,  signatureKey, verificationKey)
    #cards  = reader.create_card_with_face("testdata/manny1.bmp")
    #publicCard = cards.publicCard
    #print(publicCard.details.surName)
    #print(publicCard.details.givenName)
    #print(publicCard.details.placeOfBirth)
    #qrcode = reader.asQRCode(cards.encryptedCard)

    manny1_ftemplate = reader.computeFullTemplate("testdata/manny1.bmp")
    manny2_ftemplate = reader.computeFullTemplate("testdata/manny2.bmp")
    manny1_htemplate = reader.computeHalfTemplate("testdata/manny1.bmp")
    manny2_htemplate = reader.computeHalfTemplate("testdata/manny2.bmp")

    full_fdiff = reader.compare_face_template(manny1_ftemplate, manny2_ftemplate)
    print("full fdiff = %f " % full_fdiff);

    half_fdiff = reader.compare_face_template(manny1_htemplate, manny2_htemplate)
    print("half fdiff = %f " % half_fdiff);

    #fdiff = reader.compare_face_photo("testdata/manny1.bmp","testdata/manny2.bmp")
    #print("fdiff = %f " % fdiff)

    print("-- end --")
