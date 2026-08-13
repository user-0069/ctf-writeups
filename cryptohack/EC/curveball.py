import itertools
import json
from pwn import *
from Crypto.Util.number import isPrime, long_to_bytes, bytes_to_long
from sage.all import *
def send_json(data):
    io.sendline(json.dumps(data).encode())
def recv_json():
    return json.loads(io.recvline().decode())
io=remote("socket.cryptohack.org", 13382)
#the server just check for public key,and ensure private key != +-1, while the generator is not checked
#the order of the group is prime
#we simply send private key =2 , while faking the generator as Q_bing * inverse(2)

# secp256r1 parameters
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc # usually just -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

E = EllipticCurve(GF(p), [a, b])

Q_bing = E(
    0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 
    0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A
)
inverse_2 = (n + 1) // 2
malicious_g = Q_bing * inverse_2
print(io.recvline())
to_send ={'host': 'not_so_important', 'private_key': 2, 'curve': 'secp256r1', 'generator': [int(malicious_g[0]), int(malicious_g[1])]}
send_json(to_send)
print(io.recvall())



