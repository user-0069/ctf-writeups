# Bespoke Padding
## Description
In [RSA challenges](https://cryptohack.org/challenges/rsa/)
## Solution
The goal of this problem is to solve the equation : $(a.m+b)^{11} \equiv c ({mod} N)$.\
Note that we can take **multiple tuples of $((a,b),c,N)$** and **N is reused**. Therefore, Franklin-Reiter Related Message Attack is a good choice here.\
We only need to get parameters twice:\
Let:\
$f_1(x) = (a_1.m + b_1)^{11} - c_1$\
$f_2(x) = (a_2.m + b_2)^{11} - c_2$\
$g=gcd(f_1,f_2)$ is very likely to be linear. As $f_1$ and $f_2$ both take $m$ as a root in $Z_N[x]$, $g$ must also take $m$ as a root, and $(x-m)$ divides $g$. So we can obtain $m$ by calculating $g$.
```
from sage.all import *
from pwn import remote
from Crypto.Util.number import long_to_bytes
import json

r = remote('socket.cryptohack.org', 13386)

def send(data):
    return r.sendline(json.dumps(data).encode())

def recv():
    return json.loads(r.recvline().decode())


r.recvline()

to_send = {"option": "get_flag"}
send(to_send)
data1 = recv()

send(to_send)
data2 = recv()

a1, b1 = map(int, data1["padding"])
a2, b2 = map(int, data2["padding"])
c1 = int(data1["encrypted_flag"])
c2 = int(data2["encrypted_flag"])
N = int(data1['modulus'])


P.<x> = PolynomialRing(Zmod(N))

f1 = (a1*x + b1)**11 - c1
f2 = (a2*x + b2)**11 - c2

def monic_gcd(f, g):

    while g:
        f, g = g, f % g
    return f.monic()


g = monic_gcd(f1, f2)

g0 = g.constant_coefficient()
m = int(-g0)
flag = long_to_bytes(m)
print(flag)
r.close()
```
```
crypto{linear_padding_isnt_padding}
```


