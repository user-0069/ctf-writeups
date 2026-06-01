from pwn import *
from sage.all import *
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes

class PCG:
    def __init__(self, coeffs, modulus, seed):
        self.modulus = modulus
        self.coeffs = coeffs
        self.state = seed

    def next(self):
        result = 0
        current_power = 1

        for coeff in self.coeffs:
            result += (coeff * current_power) % self.modulus
            current_power *= self.state

        self.state = result % self.modulus
        return self.state    
#io=process(["sage", "./server.py"])
io=remote("host8.dreamhack.games", 20943)
io.recvuntil(b"[state]\n")
A=[int(io.recvline().strip().decode()) for _ in range(20)]
io.recvuntil(b"[enc]\n")
enc=io.recvline().strip().decode()
MOD=2**128
N=32
K=2**512
W=2**64
#lattice to find coeffs C[] of the PCG from the leaked states A[]
#[
#1 0 0 ... 0  K*A[0]^0      K*A[1]^0     ... K*A[19]^0
#0 1 0 ... 0  K*A[0]^1      K*A[1]^1     ... K*A[19]^1
#0 0 1 ... 0  K*A[0]^2      K*A[1]^2     ... K*A[19]^2
#...
#0 0 0 ... 1  K*A[0]^(N-1)  K*A[1]^(N-1) ... K*A[19]^(N-1)
#0 0 0 ... 0  K*MOD         0            ... 0
#0 0 0 ... 0  0             K*MOD        ... 0
#...
#0 0 0 ... 0  0             0            ... K*MOD
#0 0 0 ... W  -K*A[1]       -K*A[2]      ...-K*A[20]
#]

#target: (C1, C2, ..., CN, W, 0, 0, ..., 0)
#K is to force the right columns to be 0
#W is to force the line to use only once (CVP problem) W~C_i
mat=[]
for i in range(N):
    row=[0]*(N+1)
    row[i]=1
    for j in range(0,19):
        row.append(K*pow(A[j],i,MOD))
    mat.append(row)
for i in range(0,19):
    row=[0]*(N+20)
    row[N+1+i]=K*MOD
    mat.append(row)
row=[0]*N
row.append(W)
for j in range(1,20):
    row.append(-K*A[j])
mat.append(row)
M=Matrix(ZZ, mat)
B=M.LLL()
coeffs=[]
for row in B:
    if(row[N]==W):
        print(row)
        coeffs=row[:N]
        break
    elif(row[N]==-W):
        print(row)
        coeffs=[-x for x in row[:N]]
        break
pcg=PCG(coeffs,MOD,A[0])
for _ in range(19+1337):
    pcg.next()
key=long_to_bytes(pcg.next())
cipher=AES.new(key, AES.MODE_ECB)
pt=cipher.decrypt(bytes.fromhex(enc))
print(pt)
