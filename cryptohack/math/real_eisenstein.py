from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from sage.all import *
from pwn import *
import json
from decimal import *
getcontext().prec = 100
#this is like a knapsack problem, the secret coefficients are bounded by 256
#just construct a lattice:
#1 0 0 0 0 ... 0 0 sqrt(p1)
#0 1 0 0 0 ... 0 0 sqrt(p2)
#0 0 1 0 0 ... 0 0 sqrt(p3)
#...    
#0 0 0 0 0 ... 1 0 sqrt(pn)
#0 0 0 0 0 ... 0 1 -ct
#run LLL and it immediately spit out the flag
FLAG = "crypto{???????????????}"
PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103]
ct=1350995397927355657956786955603012410260017344805998076702828160316695004588429433
vec=[]
for i in range(len(FLAG)):
    vec.append(ZZ(int(Decimal(PRIMES[i]).sqrt()*16**64)))
vec.append(ZZ(-ct))
W=1
Mat=identity_matrix(ZZ, len(vec))*W
Mat = Mat.augment(vector(vec))
M=Mat.LLL()
for row in M.rows():
    if row[-2] == W or row[-2] == -W:
        print(row)
        for i in range(len(row)-2):
            print(chr(row[i]), end="")
        break


