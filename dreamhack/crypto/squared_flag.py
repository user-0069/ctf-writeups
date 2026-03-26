from pwn import *
from M import M
from sage.all import *
output=[46815, 54436, 41979, 52634, 9427, 38200, 30164, 30742, 37278, 27003, 60542, 47536, 61611, 9732, 18365, 23026, 41731, 25299, 3968, 11754, 5594, 13472, 47963, 62980, 14030, 45400, 27929, 22796, 6570, 1164, 9962, 23574, 19373, 17887, 58878, 20221, 52376, 54543, 36488, 25377, 56175, 20339, 35820, 26224, 7980, 43220, 8400, 51986, 54412, 3511, 43757, 22202, 19450, 39390, 19659, 27620, 47137, 36933, 11093, 6044, 4901, 2205, 13024, 12396]
mod= 0x10001
# the equation is like M*vector(flag)= vector(output)
M=Matrix(GF(mod), 64, 64, M)
print(M.rank())
# 60 
# det(M)=0 so we cannot get the inverse of M to solve the equation
# try to find an invertible 60*60 submatrix of M
M1=Matrix(GF(mod),60,60,M[0:60,3:63])
# we know the flag is in form DH{...}, therefore we can try to solve for the rest 60 chars
print(M1.rank())
# 60
# Luckily, M1 is invertible (rank=size) 
output1=[]
for i in range(60):
    cur=output[i]
    cur=(cur-ord("D")*M[i][0]+mod*mod)%mod
    cur=(cur-ord("H")*M[i][1]+mod*mod)%mod
    cur=(cur-ord("{")*M[i][2]+mod*mod)%mod
    cur=(cur-ord("}")*M[i][63]+mod*mod)%mod
    output1.append(cur)
# output1 for the corresponding M1
output1=vector(GF(mod), output1)
res=M1.inverse()*output1
print(b"DH{" + bytes(res) + b"}")
#b'DH{s0m3t1m3s_m0r3_4nd_m0r3_d4t4_1s_r3qu1r3d_t0_s0lv3_th3_syst3m}'
