"""
'EN'
uint16be : VERSION
uint8 : {'P': ChaCha20_Poly1305, 'C': ChaCha20}
uint8 : nonce_size
0x0000
uint8[24] | uint8[12] | uint8[8] : NONCE
ENCRYPTED_MESSAGE
uint8[16] | None : TAG

## ChaCha20_Poly1305 additional_data : None
"""

import io
import struct
from Crypto.Cipher import ChaCha20_Poly1305  #pycryptodome

def decrypt(src, dst, key):
    with open(src, 'rb') as rf, open(dst, 'wb') as wf:
        m, version, enc_type, nonce_size, _ = struct.unpack('>2sHsB2s', rf.read(8))
        if m != b'EN' or version != 1 or enc_type != b'P' or nonce_size != 24:
            return
        nonce = rf.read(nonce_size)
        rf.seek(-16, io.SEEK_END)
        message_size = rf.tell() - 8 - nonce_size
        tag = rf.read(16)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        rf.seek(8+nonce_size)
        
        a = 0
        while True:
            n = min(4096, message_size-a)
            if n <= 0:
                break
            e = rf.read(n)
            d = cipher.decrypt(e)
            wf.write(d)
            a += len(e)
        cipher.verify(tag)
