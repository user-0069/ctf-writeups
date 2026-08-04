from sage.all import *
from hamiltonicity import *
from pwn import *
import json
from py_ecc.optimized_bn128 import FQ,FQ2,FQ12,G1,G2, multiply, pairing 
import ast
from Crypto.Util.number import long_to_bytes
flag=""
att=0
with open("output.txt","r") as f:
    for line in f:
        data=ast.literal_eval(line)
        xG_raw=data[0]
        yG_raw=data[1]
        zG_raw=data[2]
        xG=(FQ(xG_raw[0]),FQ(xG_raw[1]),FQ(xG_raw[2]))
        yG=(FQ2(yG_raw[0]),FQ2(yG_raw[1]),FQ2(yG_raw[2]))
        zG=FQ12(zG_raw)
        if(zG==pairing(yG,xG)):
            flag+="1"
        else:
            flag+="0"
        print(f"bit {att} found")
        att+=1
dec_flag=int(flag,2)
print(long_to_bytes(dec_flag))
