from sage.all import *
import time
import ast
import hashlib
import json
from Crypto.Cipher import AES
#this problem use mov attack
# we need to find n1 n2 knowing n1*G and n2*G (classic ECDLP problem)
#in mov attack, we reduce ECC points to GF(p^k) elements, with k is the embedding degree of the curve
#k is the smallest integer such that r divides p^k - 1, where r is the order of the point G
#the embedding degree in this problem is small (2)
p = 1331169830894825846283645180581
a = -35
b = 98
E = EllipticCurve(GF(p), [a, b])
with open("output.txt") as f:
    lines = f.readlines()
    G = E(*eval(lines[0].split("tor: ")[1].replace(":",",")))
    A = E(*eval(lines[1].split("key: ")[1].replace(":",",")))
    B = E(*eval(lines[2].split("key: ")[1].replace(":",",")))
    enc = ast.literal_eval(lines[3].split("flag: ")[1])
r = G.order()
#change the field to GF(p^2) to perform MOV attack
F2.<alpha> = GF(p**2)
E2 = EllipticCurve(F2, [a, b])   

G2 = E2(G)
A2 = E2(A)

R = E2.random_point()
while R == E2(0):
    R = E2.random_point()
#tate pairing is a bilinear map that can be used to reduce the ECDLP to DLP in a finite field extension
u = G2.tate_pairing(R, r, 2)
v = A2.tate_pairing(R, r, 2)

#discrete logarithm problem in finite field extension GF(p^2)
start = time.time()
a_secret = int(pari(v).fflog(pari(u), pari(r)))
end = time.time()

print(f"\n[+] Cracked in {end - start:.1f} seconds!")
print(f"[!] Alice's private key (a): {a_secret}")
#decrypt the flag using the shared secret we found
shared_secret = a_secret * B
sha1 = hashlib.sha1()
sha1.update(str(shared_secret.xy()[0]).encode('ascii'))
key = sha1.digest()[:16]
iv=bytes.fromhex(enc["iv"])
ciphertext=bytes.fromhex(enc["encrypted_flag"])
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
print(plaintext)

