"""
Header[48]
 int64be argon2.memory_cost (KiB)
 int64be argon2.time_cost (iterations)
 int64be argon2.parallelism
 uint8[16] argon2.salt
 uint8[8] ChaCha20 NONCE
ENCRYPTED_MESSAGE

## argon2.type : argon2id
## argon2.hash_len : 32
## argon2.version : 19
## Cipher : ChaCha20
"""

import struct
import argon2 #argon2_cffi
from Crypto.Cipher import ChaCha20  #pycryptodome

def decrypt(src, dst, password:str):
    with open(src, 'rb') as rf, open(dst, 'wb') as wf:
        memory_cost, time_cost, parallelism, salt, nonce = struct.unpack('>qqq16s8s', rf.read(48))
        argon2_type = argon2.low_level.Type.ID
        version = 19
        if version != 19 or memory_cost > 1 * 1024 * 1024:
            return
        secret = password.encode()
        key = argon2.low_level.hash_secret_raw(secret=secret, salt=salt, time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, hash_len=32, type=argon2_type, version=version)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        while True:
            d = rf.read(4096)
            if len(d) == 0:
                break
            wf.write(cipher.decrypt(d))
