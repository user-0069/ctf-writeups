## Description
[aes challenge](https://cryptohack.org/challenges/aes/)
## Solution
<img width="629" height="279" alt="image" src="https://github.com/user-attachments/assets/f3baede3-f732-4537-b4f0-a44b124fef85" />

The process of AES CBC decryption

We can see that $P_i=D_k(C_i) \bigoplus C_{i-1}$. Denote $D_k(C_i)$ as $I_i$. The oracle to find $I_i$ go as follow:
* We bruteforce x and set the last byte of $C_{i-1}$ to x until the last bytes of $P_i$ become `x\01` (that is a good padding when we send to the server), the last byte of $I_i$ then become
$x \bigoplus 1$.
* We bruteforce x and set the second-last byte of $C_{i-1}$ to x until the second-last bytes of $P_i$ become `x\02` (at the same time try to modify the last byte of P_i to `x\02` to make good padding)
the last byte of $I_i$ then become $x \bigoplus 2$.
* ...

Repeat until all the 16-bytes block is recovered.\
Find the all $I_i$ to decrypted the message. (Let $C_0$ be the `iv`)
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
io=remote("socket.cryptohack.org", 13421)
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
        
        json_send({"option": "unpad", "ct": ctt})
        res = json_recv()
        
        if res["result"] == True:
            
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
        
        json_send({"option": "unpad", "ct": ctt})
        res = json_recv()
        
        if res["result"] == True:
            
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
print(to_send)


```
```
{'flag': 'crypto{if_you_ask_enough_times_you_usually_get_what_you_want}'}
```


