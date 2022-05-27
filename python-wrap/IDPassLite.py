from ctypes import *
import sys
from IDPassNative import IDPassNative
import idpasslite_pb2
import api_pb2

class Helper(object):
    def generate_encryption_key():
        key = (c_ubyte * 32)()
        IDPassNative.lib.idpass_lite_generate_encryption_key(key, len(key))
        return key

    def generate_secret_signature_keypair():
        ver = (c_ubyte * 32)()
        sig = (c_ubyte * 64)()
        IDPassNative.lib.idpass_lite_generate_secret_signature_keypair(ver, len(ver), sig, len(sig))
        return (ver, sig)

    def getPublicKey(privatekey):
        #print(type(privatekey))
        pubkey = (c_ubyte * 32)(*privatekey[32:64])
        return pubkey

class Reader(object):
    ctx = 0
    m_keySet = None

    def __init__(self, keySet):
        self.m_keySet = keySet
        keysetba = bytearray(self.m_keySet.SerializeToString())
        self.ctx = IDPassNative.lib.idpass_lite_init((c_ubyte * len(keysetba))(*keysetba), len(keysetba), None , 0)
        if self.ctx is None:
            raise ValueError('fail to initialize with specified keys')
        self.ioctl(IDPassNative.IOCTL_SET_ACL, IDPassNative.DETAIL_SURNAME | IDPassNative.DETAIL_GIVENNAME)

    def ioctl(self, cmd, param):
        #IOCTL_SET_FDIM = 0x02 # full mode
        ioctlcmd = [ cmd, param ] 
        IDPassNative.lib.idpass_lite_ioctl( self.ctx, None, (c_ubyte * len(ioctlcmd))(*ioctlcmd), len(ioctlcmd) )

    # ioctl cannot influence the setting and there is no more setting
    # since the template are already generated. There is no context 
    # this is a static method
    def compare_face_template(self, input1, input2):
        fdiff = c_float(10.0)
        status = IDPassNative.lib.idpass_lite_compare_face_template(
            (c_ubyte *len(input1))(*input1), 
            len(input1), 
            (c_ubyte *len(input2))(*input2), 
            len(input2), 
            byref(fdiff))
        if status != 0:
            raise ValueError('fail to compute face template error code [%d]' % status)
        return fdiff.value

    def computeFullTemplate(self, inputfile):
        photo = open(inputfile, "rb").read()
        # 128 floats with 4 bytes per float (128*4 = 512)
        # Do not (c_ubyte * 128*4)() as that creates two-dimensional
        # array where len(fdim) = 4 and len(fdim[0]) = 128
        fdim = (c_ubyte *512)()
        facecount = IDPassNative.lib.idpass_lite_face128dbuf( 
                        self.ctx,
                        (c_ubyte * len(photo))(*photo), 
                        len(photo), 
                        fdim
                        )

        if facecount != 1:
            raise ValueError('Dlib found %d face(s) error' % facecount)
        return bytearray(fdim)

    def computeHalfTemplate(self, inputfile):
        photo = open(inputfile, "rb").read()
        # 64 floats with 2 bytes per float (64*2 = 128)
        # Do not (c_ubyte * 64*2)() as that creates two-dimensional
        # array where len(fdim) = 2 and len(fdim[0]) = 64
        hdim = (c_ubyte *128)()
        facecount = IDPassNative.lib.idpass_lite_face64dbuf(
                        self.ctx,
                        (c_ubyte * len(photo))(*photo), 
                        len(photo), 
                        hdim
                        )

        if facecount != 1:
            raise ValueError('Dlib found %d face(s) error' % facecount)
        return bytearray(hdim)

    def computeFullTemplateAsFloats(self, inputfile):
        photo = open(inputfile, "rb").read()
        fdim = (c_float *128)()
        facecount = IDPassNative.lib.idpass_lite_face128d(
                        self.ctx,
                        (c_ubyte * len(photo))(*photo), 
                        len(photo), 
                        fdim)
        
        if facecount != 1:
            raise ValueError('Dlib found %d face(s) error' % facecount)
        return fdim    

    # The ioctl setting can switch to full or half and this influences
    # the facial biometry representation either in full 512 bytes or in
    # half 128 bytes, and from these representation the Euclidean 
    # difference is calculated. There is context as first param
    def compare_face_photo(self, inputfile1, inputfile2):
        photo1 = open(inputfile1, "rb").read()
        photo2 = open(inputfile2, "rb").read()

        fdiff = c_float(10.0)
        status = IDPassNative.lib.idpass_lite_compare_face_photo(
            self.ctx,
            (c_ubyte * len(photo1))(*photo1),
            len(photo1),
            (c_ubyte * len(photo2))(*photo2),
            len(photo2),
            byref(fdiff))
        if status != 0:
            raise ValueError('fail to compute face template error code [%d]' % status)
        return fdiff.value

    def computeHalfTemplateAsFloats(self, inputfile):
        photo = open(inputfile, "rb").read()
        hdim = (c_float *64)()
        facecount = IDPassNative.lib.idpass_lite_face64d(
                        self.ctx,
                        (c_ubyte * len(photo))(*photo), 
                        len(photo), 
                        hdim)

        if facecount != 1:
            raise ValueError('Dlib found %d face(s) error' % facecount)
        return hdim

    def create_card_with_face(self, ident):
        identba = bytearray(ident.SerializeToString())
        cardbalen = c_int(0)

        cardba = IDPassNative.lib.idpass_lite_create_card_with_face(
            self.ctx, 
            byref(cardbalen),
            (c_ubyte * len(identba))(*identba), 
            len(identba)
            )

        if cardba is None:
            raise ValueError('create card with face error')
        cards = idpasslite_pb2.IDPassCards()
        cards.ParseFromString(string_at(cardba, cardbalen.value))
        return (cards, cardba, cardbalen.value) # TODO: Improve API

    # TODO: Do something like in Java below, or probably better this is done inside
    # libidpasslite.so in C++ as the string type format is portable
    # https://github.com/idpass/idpass-lite-java/blob/develop/src/main/java/org/idpass/lite/IDPassReader.java#L515-L547
    def asQRCode(self, data):
        #inputdata = (c_ubyte * len(data)).from_buffer_copy(data)
        buf_len = c_int(0)
        qr_side_len = c_int(0)
        data_len = len(data)
        input = (c_ubyte * data_len)(*data)
        buf = IDPassNative.lib.idpass_lite_qrcodesvg(self.ctx, input, data_len)
        _strip1 = str(cast(buf,c_char_p).value)[2:]
        content = _strip1[:-1]
        return content

    def authenticateWithPin(self, cardba, cardbalen, pincode):
        details = idpasslite_pb2.CardDetails()
        buflen = c_int(0)
        buf = IDPassNative.lib.idpass_lite_verify_card_with_pin(
            self.ctx, 
            byref(buflen), 
            cardba, 
            cardbalen, 
            pincode.encode('utf-8'))
        if buflen.value == 0:
            return None
        details.ParseFromString(string_at(buf, buflen))
        return details

    def freemem(self, addr):
        IDPassNative.lib.idpass_lite_freemem(self.ctx, addr)

