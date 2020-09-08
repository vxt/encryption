"""
uint8[16] : ChaCha20_Poly1305 TAG
Header[112]
 uint32be argon2.type : Argon2d=0 Argon2i=1 Argon2id=2
 uint32be argon2.version
 uint32be argon2.memory_cost (KiB)
 uint32be argon2.time_cost (iterations)
 uint32be argon2.parallelism
 uint8[32] argon2.salt
 uint8[24] ChaCha20_Poly1305 NONCE
 zero...
ENCRYPTED_MESSAGE

## ChaCha20_Poly1305 additional_data : Header[112]
"""

import struct
import argon2 #argon2_cffi
from Crypto.Cipher import ChaCha20_Poly1305  #pycryptodome

def decrypt(src, dst, password:str):
    with open(src, 'rb') as rf, open(dst, 'wb') as wf:
        tag = rf.read(16)
        header = rf.read(112)
        argon2_type, version, memory_cost, time_cost, parallelism, salt, nonce = struct.unpack('>LLLLL32s24s36x', header)
        argon2_type = {0:argon2.low_level.Type.D, 1:argon2.low_level.Type.I, 2: argon2.low_level.Type.ID}[argon2_type]
        if version != 19 or memory_cost > 1 * 1024 * 1024:
            return
        secret = password.encode()
        key = argon2.low_level.hash_secret_raw(secret=secret, salt=salt, time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, hash_len=32, type=argon2_type, version=version)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(header)
        while True:
            d = rf.read(4096)
            if len(d) == 0:
                break
            wf.write(cipher.decrypt(d))
        cipher.verify(tag)
