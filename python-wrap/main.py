import api_pb2
import idpasslite_pb2
import IDPassLite
from ctypes import *

def KEYSET_fromFile(filename):
    keySet = api_pb2.KeySet()
    with open(filename, "rb") as binaryfile :
       ba = binaryfile.read()
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
    photo = open("florence_ID_Photo.jpg", "rb").read()
    surName = "DUPONT".encode('utf-8')
    givenName = "MARION FLORENCE".encode('utf-8')
    placeOfBirth = "FRANCE".encode('utf-8')
    pin = "12345".encode('utf-8')
    ident.surName = surName
    ident.givenName = givenName
    ident.dateOfBirth.year = 1985
    ident.dateOfBirth.month = 1
    ident.dateOfBirth.day = 1
    ident.placeOfBirth = placeOfBirth
    ident.pin = pin
    ident.photo = photo
    extra = idpasslite_pb2.Pair()
    extra.key = "Sex"
    extra.value = "F"
    ident.pubExtra.append(extra)
    extra.key = "Nationality"
    extra.value = "French"
    ident.pubExtra.append(extra)
    extra.key = "Date Of Issue"
    extra.value = "02 JAN 2025"
    ident.pubExtra.append(extra)
    extra.key = "Date Of Expiry"
    extra.value = "01 JAN 2035"
    ident.pubExtra.append(extra)
    extra.key = "ID"
    extra.value = "SA437277"
    ident.pubExtra.append(extra)
    # SS Number field only visible after authentication
    extra.key = "SS Number"
    extra.value = "2 85 01 75 116 001 42"
    ident.privExtra.append(extra) 
    extra.key = "contract"
    extra.value = "0x28BFC23c29D6859E3f43d2d1714d019a7c44ba0E"
    ident.privExtra.append(extra) 
    return ident

if __name__ == "__main__":
    keySet = KEYSET_fromFile("demokeys.bin") # Load matching keyset from Android reader app
    reader = IDPassLite.Reader(keySet)

    ident1 = getIdent1() # Use this identity details as an example

    # Notes: create_card_with_face is temporarily returning a tuple as I need
    # the buf array to authenticate back to the card via its pin code
    # cards, buf, buflen  = reader.create_card_with_face(ident1) 

    card  = reader.create_card_with_face(ident1) 
    svg = card.asQRCodeSVG()
    open("qrcode.svg","w").write(svg)
    
    # publicCard = cards.publicCard
    # print(publicCard.details.surName)
    # print(publicCard.details.givenName)
    # print(publicCard.details.placeOfBirth) # Prior to authentication, placeOfBirth is not visible
    # qrcodesvg = reader.asQRCode(buf, buflen)
    # open("qrcode.svg","w").write(qrcodesvg)

    # c = reader.authenticateWithPin(buf, buflen, "12345")
    # if c is not None:
    #     print(c.placeOfBirth) # After authentication, placeOfBirth is now visible
    # else:
    #     print("wrong pin code")
