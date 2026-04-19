## Description
[challenge](https://dreamhack.io/wargame/challenges/1881)
## Solution
We can calculate the x coordinate of `Q` by the formula:\
$$\Huge{x_{Q}=x_{2P} = \left( \frac{3x_P^2 + a}{2y_P} \right)^2 - 2x_P = \frac{(3x_P^2 + a)^2}{4(x_P^3 + ax_P + b)} - 2x_P}$$\
So there is a function $f_i$ such that:\
$f(a_i \cdot key1+b_i) = c_i \cdot key2+ d_i$\
which means we can find $g_i(key1) = key2$ from the above equations. Solve $g_i(x) - g_j(x) =0$ to find $key1$. 10 pairs `(P,Q)` are too much for this problem.
```
from sage.all import *
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

Zp = Zmod(p)
P256 = EllipticCurve(Zp, [a, b])

text="""
...
...
"""
lines=text.split('\n')[1:-1]
Pa=[0]*10
Pb=[0]*10
Qa=[0]*10
Qb=[0]*10
for i in range(10):
    Pa[i]=Integer(lines[i*2].split(" ")[2])
    Pb[i]=Integer(lines[i*2].split(" ")[6])
    Qa[i]=Integer(lines[i*2+1].split(" ")[2])
    Qb[i]=Integer(lines[i*2+1].split(" ")[6])
P.<x> = PolynomialRing(GF(p))
Frac=FractionField(P)
Px=[P(Pa[i]*x+Pb[i]) for i in range(10)]
Qx=[Frac((3*Px[i]^2+a)^2/(4*(Px[i]^3+a*Px[i]+b)))-Frac(2*Px[i]) for i in range(10)]
k2=[Frac((Qx[i]-Qb[i])/Qa[i]) for i in range(10)]
eq=k2[0]-k2[1]
kk=eq.numerator().roots()
eq1=k2[0]-k2[2]
kk1=eq1.numerator().roots()
common_root=[]
for r in kk:
    if r in kk1:
        common_root.append(r)
print(common_root)
key1=common_root[0][0]
key2=k2[0].subs(x=key1)
key=int(key1) ^^ int(key2)
print(f"Flag is DH{{{key:064x}}}")

```


