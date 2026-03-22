from pwn import *
import requests
from sage.all import *

BASE_URL = "https://aes.cryptohack.org"

# --- GF(2^128) ---
P = PolynomialRing(GF(2), names=('x',))
x = P.gen()
poly = x**128 + x**7 + x**2 + x + 1
F = GF(2**128, modulus=poly, names=('a',))
a = F.gen()

def decrypt(nonce, ciphertext, tag, associated_data):
    url = f"{BASE_URL}/forbidden_fruit/decrypt/{nonce}/{ciphertext}/{tag}/{associated_data}/"
    response = requests.get(url)
    return response.json()

def encrypt(plaintext):
    url = f"{BASE_URL}/forbidden_fruit/encrypt/{plaintext}/"
    response = requests.get(url)
    return response.json()
# conversion from hex to GF(2^128) and back
def hex_to_gf2n(hex_str):
    val = int(hex_str, 16)
    reversed_bin = bin(val)[2:].zfill(128)[::-1]
    k = int(reversed_bin, 2)
    return F(P(ZZ(k).bits()))

def gf2n_to_hex(element):
    bits = P(element).list()
    bits = bits + [0] * (128 - len(bits))
    bin_str = "".join(str(b) for b in bits)
    return "{:032x}".format(int(bin_str, 2))


# Tag = AD*y^3 + C*y^2 + L*y + S
# AD here is the associated data, which is always 'CryptoHack' in this chall
# C is the ciphertext
# L is len(AD)||len(C) 
# S is some mask, stay the same with nonce reuse
# y is the authentication key, reveal the keystream E_K(00..000)
# + operation here same as XOR
# the idea is tag1 + tag2 = (C1 + C2)*y^2 
# (same AD,same S, same L) => y^2 = (tag1 + tag2) / (C1 + C2) ->find y
# fake a ciphertext for "give me the flag" with the same keystream, then forge a tag for it with the same y^2
# that's enough to grab the flag


# Send 2 plaintexts
p1_hex = "ac" * 16
p2_hex = "51" * 16

kk1 = encrypt(p1_hex)
c1_hex = kk1['ciphertext']
tag1_hex = kk1['tag']
nonce = kk1['nonce']
associated_data = kk1['associated_data']

kk2 = encrypt(p2_hex)
c2_hex = kk2['ciphertext']
tag2_hex = kk2['tag']


c1_gf = hex_to_gf2n(c1_hex)
c2_gf = hex_to_gf2n(c2_hex)
tag1_gf = hex_to_gf2n(tag1_hex)
tag2_gf = hex_to_gf2n(tag2_hex)

# Find y
key_squared = (tag1_gf + tag2_gf) / (c1_gf + c2_gf)
key = key_squared.sqrt()
print(f"[+] Authentication Key (y): {gf2n_to_hex(key)}")


# Forge Ciphertext (Keystream = P1 ^ C1 -> C_forge = P_forge ^ Keystream)
p_forge_bytes = b"give me the flag"
p1_bytes = bytes.fromhex(p1_hex)
c1_bytes = bytes.fromhex(c1_hex)

c_forge_bytes = xor(p_forge_bytes, p1_bytes, c1_bytes)
c_forge_hex = c_forge_bytes.hex()
print(f"[+] Fake Ciphertext: {c_forge_hex}")


# Tag_forge = Tag1 + (C1 + C_forge) * y^2
c_forge_gf = hex_to_gf2n(c_forge_hex)

tag_forge_gf = tag1_gf + (c1_gf + c_forge_gf) * key_squared
tag_forge_hex = gf2n_to_hex(tag_forge_gf)
print(f"[+] Fake Tag:      {tag_forge_hex}")

result = decrypt(nonce, c_forge_hex, tag_forge_hex, associated_data)
print(f"Server Response: {result}")

if 'plaintext' in result:
    flag = bytes.fromhex(result['plaintext']).decode()
    print(f"\n{flag}")

#crypto{https://github.com/attr-encrypted/encryptor/pull/22}
