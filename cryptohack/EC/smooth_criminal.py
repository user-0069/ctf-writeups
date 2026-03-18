from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
from collections import namedtuple
from sage.all import *
from random import randint
import hashlib
import os

# Create a simple Point class to represent the affine points.
Point = namedtuple("Point", "x y")

# The point at infinity (origin for the group law).
O = 'Origin'
iv= '07e2628b590095a5e332d397b8a59aa7'
enc= '8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af'

FLAG = b'crypto{??????????????????????????????}'


def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data

def decrypt_flag(shared_secret: int):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    iv=bytes.fromhex('07e2628b590095a5e332d397b8a59aa7')
    ct=bytes.fromhex(enc)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ct)
    return plaintext

    


# Define the curve
p = 310717010502520989590157367261876774703
a = 2
b = 3
E=EllipticCurve(GF(p),[a,b])
# Generator
g_x = 179210853392303317793440285562762725654
g_y = 105268671499942631758568591033409611165
G = E(g_x, g_y)


# Bob's public key
b_x = 272640099140026426377756188075937988094
b_y = 51062462309521034358726608268084433317
B = E(b_x, b_y)

gn=E(280810182131414898730378982766101210916, 291506490768054478159835604632710368904)
print(E.order().factor())
# 2^2 * 3^7 * 139 * 165229 * 31850531 * 270778799 * 179317983307
# quite smooth curve order -> DLP idea works
k=gn.log(G)

bn=k*B

print(decrypt_flag(bn.x()))
# b'crypto{n07_4ll_curv3s_4r3_s4f3_curv3s}\n\n\n\n\n\n\n\n\n\n'




