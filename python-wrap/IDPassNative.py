# https://github.com/newlogic42/lab_idpass_lite/blob/master/lib/src/idpass.h

import ctypes
import ctypes.util
import sys,os,signal

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)

class IDPassNative(object):
    try:
        # lib = CDLL("lib/libidpasslite.so")
        # Linux   -> export LD_LIBRARY_PATH=/path/to/lib/:$LB_LIBRARY_PATH
        # Windows -> set PATH=c:/path/to/lib;%PATH%
        idpasslite = ctypes.util.find_library('idpasslite') or ctypes.util.find_library('libidpasslite')

        if idpasslite is None:
            raise ValueError('Unable to find idpasslite library')

        lib = ctypes.cdll.LoadLibrary(idpasslite)
        if not lib._name:
            raise ValueError('Unable to correctly load idpasslite library')

        signal.signal(signal.SIGINT, signal_handler)

        # These argtypes/restype signatures declarations here are optional but helps in a certain way
        lib.idpass_lite_ioctl.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int ]
        lib.idpass_lite_ioctl.restype = ctypes.POINTER(ctypes.c_ubyte)

        lib.idpass_lite_compare_face_photo.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_float) ]
        lib.idpass_lite_compare_face_photo.restype = ctypes.c_int

        # doesn't need ctx and can be invoke as a class method just like the generate key methods
        lib.idpass_lite_compare_face_template.argtypes = [ ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_float) ]
        lib.idpass_lite_compare_face_template.restype = ctypes.c_int

        lib.idpass_lite_face128d.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_float) ]
        lib.idpass_lite_face128d.restype = ctypes.c_int

        lib.idpass_lite_face64d.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_float) ]
        lib.idpass_lite_face64d.restype = ctypes.c_int

        # since output size already known, then caller must pre-allocate the last param as 128*4 bytes and then pass into function
        lib.idpass_lite_face128dbuf.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte) ]
        lib.idpass_lite_face128dbuf.restype = ctypes.c_int

        # since output size already known, then caller must pre-allocate the last param as 64*2 bytes and then pass into function
        lib.idpass_lite_face64dbuf.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte) ]
        lib.idpass_lite_face64dbuf.restype = ctypes.c_int

        lib.idpass_lite_generate_encryption_key.argtypes = [ ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int ]
        lib.idpass_lite_generate_encryption_key.restype = ctypes.c_int

        lib.idpass_lite_generate_secret_signature_keypair.argtypes = [ ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
        lib.idpass_lite_generate_secret_signature_keypair.restype = ctypes.c_int

        lib.idpass_lite_init.argtypes = [ ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
        lib.idpass_lite_init.restype = ctypes.c_void_p

        lib.idpass_lite_create_card_with_face.argtypes = [ 
            ctypes.c_void_p, 
            ctypes.POINTER(ctypes.c_int), 
            ctypes.POINTER(ctypes.c_ubyte), 
            ctypes.c_int
            ]

        lib.idpass_lite_create_card_with_face.restype = ctypes.POINTER(ctypes.c_ubyte)

        lib.idpass_lite_verify_card_with_pin.argtypes = [ 
            ctypes.c_void_p, 
            ctypes.POINTER(ctypes.c_int), 
            ctypes.POINTER(ctypes.c_ubyte), 
            ctypes.c_int, 
            ctypes.POINTER(ctypes.c_char) 
            ]
        lib.idpass_lite_verify_card_with_pin.restype = ctypes.POINTER(ctypes.c_ubyte)

        lib.idpass_lite_qrpixel2.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_int) ]
        lib.idpass_lite_qrpixel2.restype = ctypes.POINTER(ctypes.c_ubyte)

        lib.idpass_lite_freemem.argtypes = [ ctypes.c_void_p, ctypes.c_void_p ]
        lib.idpass_lite_freemem.restype = None
    except Exception as e:
        print(str(e))
        sys.exit(1)
