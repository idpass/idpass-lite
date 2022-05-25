import api_pb2
import IDPassLite

def KEYSET_fromFile(filename):
    keySet = api_pb2.KeySet()
    with open(filename, "rb") as binaryfile :
       buf = bytearray(binaryfile.read())
    keySet.ParseFromString(buf)
    return keySet

def KEYSET_fromRandom():
    keySet = api_pb2.KeySet()
    encryptionKey = IDPassLite.Helper.generate_encryption_key()
    (verificationKey, signatureKey) = IDPassLite.Helper.generate_secret_signature_keypair()
    ba = api_pb2.byteArray()
    ba.val = bytes(verificationKey)
    ba.typ = api_pb2.byteArray.Typ.ED25519PUBKEY
    keySet.encryptionKey = bytes(encryptionKey) 
    keySet.signatureKey = bytes(signatureKey)
    keySet.verificationKeys.append(ba) 
    return keySet

if __name__ == "__main__":
    keySet = KEYSET_fromFile("demokeys.bin")
    # keySet = KEYSET_fromRandom()
    reader = IDPassLite.Reader(keySet)

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
