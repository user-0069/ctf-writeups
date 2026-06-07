from pwn import *
from sage.all import *
import json
import ast
from Crypto.Util.number import long_to_bytes

context.log_level = 'debug'
q = 0x10001

with open('output.txt', 'r') as f:
    obj = json.load(f)

A_raw = ast.literal_eval(obj['A'])
b_raw = ast.literal_eval(obj['b'])
#this is like a knapsack problem, with small errors, which can be found by LLL
#the matrix size is too big, so we need reduction to make the modulo-wapping matrix smaller
#the secret is the solution of the knapsack problem
m_samples = 30 #sample size, must use to reduce the modulo wrapping matrix size
A_raw = A_raw[:m_samples]
b_raw = b_raw[:m_samples]

n = len(A_raw[0])
m = len(b_raw)

A = Matrix(ZZ, A_raw)
b = vector(ZZ, b_raw)

W = 1 #weight to scale, but 1 is enough

Top = block_matrix([[identity_matrix(ZZ, m) * q, matrix(ZZ, m, 1)]])
Mid = block_matrix([[A.transpose(),              matrix(ZZ, n, 1)]])
Bot = block_matrix([[matrix(ZZ, 1, m, (-b).list()), matrix(ZZ, [[W]])]])

M = block_matrix([[Top], [Mid], [Bot]])

#extract the coeff, which is the solution of the knapsack problem.
L, U = M.LLL(transformation=True)

secret = None

for i in range(L.nrows()):
    #when b is only used once, as this is CVP problem
    if L[i][-1] == W:
        secret = U[i][m : m+n]
        break
    elif L[i][-1] == -W:
        secret = -U[i][m : m+n]
        break

if secret is not None:
    flag_int = 0
    for x in reversed(secret.list()):
        val = int(x) % q
        flag_int = flag_int * q + val
    print(long_to_bytes(flag_int))
