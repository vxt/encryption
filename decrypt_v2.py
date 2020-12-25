"""
'EN'
uint16be : VERSION : 2
uint8 : {'P': ChaCha20_Poly1305, 'C': ChaCha20}
uint8 : nonce_size
uint16be : 0x0000
uint8[24] | uint8[12] | uint8[8] : KEY NONCE
ENCRYPTED_MESSAGE
    uint8[32] : DATA KEY
    uint8[24] | uint8[12] | uint8[8] : DATA NONCE
uint8[16] | None : TAG
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
        if m != b'EN' or version != 2 or enc_type != b'P' or nonce_size != 24:
            return
        key_nonce = rf.read(nonce_size)
        e = rf.read(32+nonce_size)
        key_tag = rf.read(16)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=key_nonce)
        d = cipher.decrypt(e)
        cipher.verify(key_tag)
        data_key = d[:32]
        data_nonce = d[32:]

        rf.seek(-16, io.SEEK_END)
        message_size = rf.tell() - 8 - nonce_size * 2 - 32 - 16
        tag = rf.read(16)
        cipher = ChaCha20_Poly1305.new(key=data_key, nonce=data_nonce)
        rf.seek(8 + nonce_size * 2 + 32 + 16)
        
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
