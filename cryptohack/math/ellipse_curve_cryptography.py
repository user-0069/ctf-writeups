from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import *
from hashlib import sha1
import random
import os

from collections import namedtuple
from sage.all import *
#Ellipse curve is not elliptic curve!
#This is conic section curve
#the point here could be represented as x+sqrt(D)*y, which make sense with the point addition: its like multiplication!
#D = 529 = 23^2, so D is a quadratic residue mod p
#we can flatten the point to a single number by x+sqrt(D)*y, while p-1 is quite smooth, simple for DLP to get n_a
#compute B*n_a to get shared secret,then obtain the flag
Point = namedtuple("Point", "x y")
def point_addition(P, Q):
    Rx = (P.x*Q.x + D*P.y*Q.y) % p
    Ry = (P.x*Q.y + P.y*Q.x) % p
    return Point(Rx, Ry)


def scalar_multiplication(P, n):
    Q = Point(1, 0)
    while n > 0:
        if n % 2 == 1:
            Q = point_addition(Q, P)
        P = point_addition(P, P)
        n = n//2
    return Q
p = 173754216895752892448109692432341061254596347285717132408796456167143559
D = 529
d = 23
F=GF(p)
G = Point(29394812077144852405795385333766317269085018265469771684226884125940148,94108086667844986046802106544375316173742538919949485639896613738390948)
enc_flag = {'iv': '64bc75c8b38017e1397c46f85d4e332b', 'encrypted_flag': '13e4d200708b786d8f7c3bd2dc5de0201f0d7879192e6603d7c5d6b963e1df2943e3ff75f7fda9c30a92171bbbc5acbf'}
A= Point(x=155781055760279718382374741001148850818103179141959728567110540865590463, y=73794785561346677848810778233901832813072697504335306937799336126503714)
B= Point(x=171226959585314864221294077932510094779925634276949970785138593200069419, y=54353971839516652938533335476115503436865545966356461292708042305317630)
AA=F(A.x+23*A.y)
GG=F(G.x+23*G.y)
n_A=AA.log(GG)
shared_secret = scalar_multiplication(B, n_A).x
key = sha1(str(shared_secret).encode('ascii')).digest()[:16]
iv = bytes.fromhex(enc_flag['iv'])
cipher = AES.new(key, AES.MODE_CBC, iv)
enc=bytes.fromhex(enc_flag['encrypted_flag'])
flag = unpad(cipher.decrypt(enc),16)
print(flag)



