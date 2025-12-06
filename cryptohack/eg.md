# Export-grade

## Description

![](/cryptohack/img/export-grade-des.png)

## My Solution
I send to Bob the only option **DH64** to make the Diffie-Hellman key size as small as possible. 
```
~$ nc socket.cryptohack.org 13379 
Intercepted from Alice: {"supported": ["DH1536", "DH1024", "DH512", "DH256", "DH128", "DH64"]}
Send to Bob: {"supported": ["DH64"]}
Intercepted from Bob: {"chosen": "DH64"}
Send to Alice: {"chosen": "DH64"}
Intercepted from Alice: {"p": "0xde26ab651b92a129", "g": "0x2", "A": "0x77cabb6add786395"}
Intercepted from Bob: {"B": "0x8a56a1f5c674a937"}
Intercepted from Alice: {"iv": "a8a4e385fb2ef4c963975c89e4a56fa6", "encrypted_flag": "99cdcdee6ea322586bd7a8c6423ad55919db98f6c5b960854267f8be7df8c8c4"}
```
The key size is small enough to use discrete_log (which has time complexity of O($\sqrt{p} log m$))
```
from sympy.ntheory import discrete_log
g= int("0x2",16)
A= int("0x77cabb6add786395",16)
B= int("0x8a56a1f5c674a937",16)
p= int("0xde26ab651b92a129",16)
b= discrete_log(p,B,g)
print(b)
```
