from pwn import *
from sage.all import *
import json
import ast
context.log_level='debug'
# dimension
n = 64
# plaintext modulus
p = 257
# ciphertext modulus
q = 0x10001
V=VectorSpace(GF(q), 64)
io=remote('socket.cryptohack.org', 13411)
def sendjson(data):
    io.sendline(json.dumps(data).encode())
def recvjson():
    return json.loads(io.recvline().decode())
def encrypt(m):
    sendjson({"option":"encrypt","message":m})
    return recvjson()
def get_flag(index:int):
    sendjson({"option":"get_flag","index":index})
    return recvjson()
#just simple algebra
A=[]
B=[]
io.recvuntil(b'flag?\n')
for i in range(n):
    kk=encrypt(0)
    aa=kk['A']
    bb=kk['b']
    bb=int(bb)
    aa=ast.literal_eval(aa)
    A.append(aa)
    B.append([bb])
A=Matrix(GF(q), A)
B=Matrix(GF(q), B)

S=A.inverse()*B
i=0
flag=""
while True:
    kk=get_flag(i)
    if('error' in kk):
        break
    aa=kk['A']
    aa=ast.literal_eval(aa)
    bb=int(kk['b'])
    aa=vector(GF(q), aa)
    m=bb-(aa*S)[0]
    flag+=chr(m)
    i+=1
print(flag)




