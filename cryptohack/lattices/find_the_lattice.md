# Find the lattice
## Description
In [Lattices challenges](https://cryptohack.org/challenges/post-quantum/)
## Solution
In the `gen_key()` function we see $h=\frac{g}{f} ({mod} q)$, which means $g = k.q + h.f$ for some $k$.
We have the equation:

$k.(0,q) + f.(1,h) = (f,g)$

We focus on the lattice with span ${(0,q),(1,h)}$. Note that $f,g$ are very small compared to $q,h$ ; so LLL algorithm works in this case to find $f,g$. Knowing $f,g$ ; we can easily decrypt the message with `decrypt()` function provided
in `source.py`.
```
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from sage.all import *
import random
import math



def decrypt(q, h, f, g, e):
    a = (f*e) % q
    m = (a*inverse(f, g)) % g
    return m


q, h = (7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257, 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800)

e = 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523

A=Matrix(ZZ,[[0,q],[1,h]])
A=A.LLL()
f=int(A[0][0])
g=int(A[0][1])
m=decrypt(q,h,f,g,e)
print(long_to_bytes(m))
```
```
crypto{Gauss_lattice_attack!}
```

