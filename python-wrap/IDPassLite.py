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

    def create_card_with_face(self, inputfile):
        photo = open(inputfile, "rb").read()
        buf_len = c_int(0)
        surname = "Doe".encode('utf-8')
        givenname = "John".encode('utf-8')
        dob = "1980/12/17".encode('utf-8')
        place = "USA".encode('utf-8')
        pin = "12345".encode('utf-8')

        buf = IDPassNative.lib.idpass_lite_create_card_with_face(
            self.ctx, 
            byref(buf_len),
            surname, 
            givenname, 
            dob, 
            place, 
            pin, 
            (c_ubyte * len(photo))(*photo), 
            len(photo), 
            None,
            0,
            None,
            0)
        if buf is None:
            raise ValueError('create card with face error')
        buf = string_at(buf, buf_len.value)
        cards = idpasslite_pb2.IDPassCards()
        cards.ParseFromString(buf)
        return cards

    def asQRCode(self, data):
        #inputdata = (c_ubyte * len(data)).from_buffer_copy(data)
        buf_len = c_int(0)
        qr_side_len = c_int(0)
        data_len = len(data)
        input = (c_ubyte * data_len)(*data)
        buf = IDPassNative.lib.idpass_lite_qrpixel2(self.ctx, byref(buf_len), input, data_len, byref(qr_side_len))
        #print("buf_len = %d " % buf_len.value)
        #print("qr_side_len = %d " % qr_side_len.value)
        buf = string_at(buf, buf_len.value)
        return buf, qr_side_len

    def freemem(self, addr):
        IDPassNative.lib.idpass_lite_freemem(self.ctx, addr)

