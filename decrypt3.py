"""
NONCE : uint8[24]
ENCRYPTED_MESSAGE
TAG : uint8[16]

## ChaCha20_Poly1305 additional_data : NONCE
"""

import io
import struct
from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305  #pycryptodome

def decrypt(src, dst, key):
    with open(src, 'rb') as rf, open(dst, 'wb') as wf:
        rf.seek(-16, io.SEEK_END)
        message_size = rf.tell() - 24
        tag = rf.read(16)
        rf.seek(0)
        nonce = rf.read(24)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(nonce)
        
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
