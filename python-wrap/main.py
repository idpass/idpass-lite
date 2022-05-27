import api_pb2
import IDPassLite
from ctypes import *

def KEYSET_fromFile(filename):
    keySet = api_pb2.KeySet()
    with open(filename, "rb") as binaryfile :
       ba = bytearray(binaryfile.read())
    keySet.ParseFromString(ba) 
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

def getIdent1():
    ident = api_pb2.Ident()
    photo = open("testdata/manny1.bmp", "rb").read()
    surName = "Doe".encode('utf-8')
    givenName = "John".encode('utf-8')
    dateOfBirth = "1980/12/17".encode('utf-8')
    placeOfBirth = "USA".encode('utf-8')
    pin = "12345".encode('utf-8')
    ident.surName = surName
    ident.givenName = givenName
    # ident.dateOfBirth = dateOfBirth
    ident.placeOfBirth = placeOfBirth
    ident.pin = pin
    return ident

def faceTemplateTest(reader):
    manny1_ftemplate = reader.computeFullTemplate("testdata/manny1.bmp")
    manny2_ftemplate = reader.computeFullTemplate("testdata/manny2.bmp")
    manny1_htemplate = reader.computeHalfTemplate("testdata/manny1.bmp")
    manny2_htemplate = reader.computeHalfTemplate("testdata/manny2.bmp")
    full_fdiff = reader.compare_face_template(manny1_ftemplate, manny2_ftemplate)
    print("full fdiff = %f " % full_fdiff);
    half_fdiff = reader.compare_face_template(manny1_htemplate, manny2_htemplate)
    print("half fdiff = %f " % half_fdiff);

if __name__ == "__main__":
    keySet = KEYSET_fromFile("demokeys.bin")
    reader = IDPassLite.Reader(keySet)

    ident1 = getIdent1()

    # Notes: create_card_with_face is temporarily returning a tuple as I need
    # the buf array to authenticate back to the card via its pin code
    cards, buf, buflen  = reader.create_card_with_face(ident1) 
    
    publicCard = cards.publicCard
    print(publicCard.details.surName)
    print(publicCard.details.givenName)
    print(publicCard.details.placeOfBirth) # Prior to authentication, placeOfBirth is not visible
    qrcodesvg = reader.asQRCode(cards.encryptedCard)
    open("qrcode.svg","w").write(str(cast(qrcodesvg,c_char_p).value))

    c = reader.authenticateWithPin(buf, buflen, "12345")
    if c is not None:
        print(c.placeOfBirth) # After authentication, placeOfBirth is now visible
    else:
        print("wrong pin code")
