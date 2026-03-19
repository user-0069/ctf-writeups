## Description
[aes challenge](https://cryptohack.org/challenges/aes/)
## Solution
The problem is almost the same with "Pad Thai" challenge. The only different is that the `check_padding` function return some noise information. If the padding is true, it will return `True`.
However, in case of invalid padding, it return `True` with a probability of 0.6 . If we ask thee server 15 times, the chance that an invalid padding pass all 15 checks is only $0.6^{15}$ (so small!).
So we just need to do the same as previous challenge, adding more checks. (It will not exceed the query limit).
```
from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
from collections import namedtuple
from sage.all import *
from random import randint
import hashlib
import os
from pwn import *
import json
io=remote("socket.cryptohack.org", 13422)
def json_recv():
    line = io.readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    io.sendline(request)

print(io.readline())
to_send={
    "option": "encrypt"
}
json_send(to_send)
kk=json_recv()
kk=kk["ct"]
iv=bytes.fromhex(kk[:32])
c1=bytes.fromhex(kk[32:64])
c2=bytes.fromhex(kk[64:])

iv_list = [int(z) for z in iv]
c1_list = [int(z) for z in c1]
c2_list = [int(z) for z in c2]
pot=[ord(c) for c in "0123456789abcdef"] #plaintext is hex string ->reduced search space for each char
I = [0] * 16

for i in reversed(range(16)):
    val_pad = 16 - i  
    cur = iv_list[:] 
    for j in range(i + 1, 16):
        cur[j] = I[j] ^ val_pad 
       
    for j in range(256):
        cur[i] = j
        I_guess=j^val_pad
        if(I_guess^iv_list[i] not in pot):
            continue
        
        ctt = "".join("{:02x}".format(z) for z in (cur + c1_list))
        cnt=0
        for _ in range(15):
            json_send({"option": "unpad", "ct": ctt})
            res = json_recv()
            cnt+=res["result"]
            if(res["result"]==False):
                break
        if cnt == 15:
            
            I[i] = j ^ val_pad 
            print(f"Found byte {i}: hex={hex(j)}, I={hex(I[i])}, P={hex(I[i] ^ iv_list[i])}")
            break
p1 = bytes([I[idx] ^ iv_list[idx] for idx in range(16)])
for i in reversed(range(16)):
    val_pad = 16 - i  
    cur = c1_list[:] 
    for j in range(i + 1, 16):
        cur[j] = I[j] ^ val_pad 
        

    for j in range(256):
        cur[i] = j
        I_guess=j^val_pad
        if(I_guess^c1_list[i] not in pot):
            continue
       
        ctt = "".join("{:02x}".format(z) for z in (cur + c2_list))
        cnt=0
        for _ in range(15):
            json_send({"option": "unpad", "ct": ctt})
            res = json_recv()
            cnt+=res["result"]
            if(res["result"]==False):
                break
        if cnt == 15:
            
            I[i] = j ^ val_pad 
            print(f"Found byte {i}: hex={hex(j)}, I={hex(I[i])}, P={hex(I[i] ^ c1_list[i])}")
            break
p2 = bytes([I[idx] ^ c1_list[idx] for idx in range(16)])
print(p1+p2)
to_send={
    "option": "check",
    "message": (p1+p2).decode()
}
json_send(to_send)
print(json_recv())

```
```
{'flag': 'crypto{even_a_faulty_oracle_leaks_all_information}'}
```
