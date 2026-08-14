from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import *
from hashlib import sha1
from sage.all import *
from pwn import *
import json
def send_json(data):
    io.sendline(json.dumps(data).encode())
def recv_json():
    return json.loads(io.recvline().decode())
#it looks like classic DLP problem in prime field, but not checking n prime is fatal
#g need to have order q, so q must be a divisor of phi(n)
#what if we choose n=q^2? phi(n) = q*(q-1)!!
#the math now is like the p-adic log problem
#just let g=q+1, then g^x = (q+1)^x = 1 + x*q mod q^2, so we can recover x easily
#the script is so simple, but the idea is really interesting!

io = remote("socket.cryptohack.org", 13403)
q=int(io.recvline().decode().split("\"")[1],16)
send_json({"g":hex(q+1),"n":hex(q**2)})
y=int(io.recvline().decode().split("\"")[1],16)
send_json({"x":hex((y-1)//q)})
print(io.recvall())

