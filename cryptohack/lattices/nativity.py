from pwn import *
from sage.all import *
import json
import ast
from Crypto.Util.number import long_to_bytes

context.log_level = 'debug'
q = 0x10000
def decrypt(sk, ct):
    return sum(s * c for s, c in zip(sk, ct)) &1
with open('public_key.txt', 'r') as f:
    A_rows = [list(map(int, line.split())) for line in f if line.strip()]

with open('ciphertexts.txt', 'r') as f:
    ct_rows = [list(map(int, line.split())) for line in f if line.strip()]

#The solution is almost the same as bounded noise
#But this chall use gaussian noise instead of binary noise
m_samples = 180 # need it to be big now to catch the noise 
A = Matrix(ZZ, A_rows[:-1])
b = vector(ZZ, A_rows[-1])


A = A[:, :m_samples]
b = b[:m_samples]

m = A.ncols()
n = A.nrows()

W = 4 
# sigma of the gaussian noise is 2.3, so the average of 2*e (b - <a,s> = 2e) is around 4.6  so this W is to
# make the resulting vector balanced
Top = block_matrix([[identity_matrix(ZZ, m) * q, matrix(ZZ, m, 1)]])
Mid = block_matrix([[A,              matrix(ZZ, n, 1)]])
Bot = block_matrix([[matrix(ZZ, 1, m, (-b).list()), matrix(ZZ, [[W]])]])

M = block_matrix([[Top], [Mid], [Bot]])
#the matrix construction is similar to the one in Bounded Noise chall
L, U = M.LLL(transformation=True)
print(L)
for i in range(L.nrows()):
    if L[i][-1] == W:
        secret = U[i][m : m+n]
        break
    elif L[i][-1] == -W:
        secret = -U[i][m : m+n]
        break
sk=secret.list()
sk.append(-1)
pt="" 
for row in ct_rows:
    pt+=str(decrypt(sk, row))
print(long_to_bytes(int(pt, 2)))

