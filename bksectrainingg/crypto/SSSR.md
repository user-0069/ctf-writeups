## Description
[sssr.py](https://training.bksec.vn/apiv2/files/local/rRga6uVwU12u0prE-5VkV?iat=1771427400&sig=Hmg0c0NF8tKNFtsa2zUMxFBcprbtdiurbvLD5AC7CYc)\
`103.77.175.40 7201`
## My solution
The difficulty in this problem is that the polynomial has degree $d$ while we only know $d$ points, which is impossible to retrieve it.
However, I come up with an idea: 
* denote $Q(x^2) = \frac{P(x) - P(-x)}{2} \cdot x$. $Q(x^2)$ contains all the coefficients in odd positions of $P(x)$ and has degree $d/2$.
* We are allowed to get $d$ points of $P(x)$, which help us to get d/2 points of $Q(x)$ ($P(i)$ and $P(-i)$ give $Q(i^2)$ ).
* The trick is, we are not allowed to get $P(0)$, however, we know $Q(0)=0$, adding one more points for us to construct $Q(x)$.
* What about the even coefficients? Maybe we don't need to care about that. Just keep connecting to the server until we are lucky enough
to have odd `idx`s. Find the number that appears in both polynomials $Q$ to obtain `s`.
```
p = 2**128 - 6719
K=GF(p)
R=PolynomialRing(K,'z')
while(True):
    r=remote("103.77.175.40" ,7201)
    r.sendline(b"100")
    points=[[0,0]]
    for i in range(1,51):
        r.sendline(str(i).encode())
        line=r.recvline().strip().decode()
        k1=int(line,10)
        r.sendline(str(-i+p).encode())
        line=r.recvline().strip().decode()
        k2=int(line,10)
        kk=K(k1-k2)/2*i
        points.append([K(i*i),kk])
    poly1=R.lagrange_polynomial(points)
    r.sendline(b"12345")
    print(r.recvline())
    r.sendline(b"100")
    points=[[0,0]]
    for i in range(1,51):
        r.sendline(str(i).encode())
        line=r.recvline().strip().decode()
        k1=int(line,10)
        r.sendline(str(-i+p).encode())
        line=r.recvline().strip().decode()
        k2=int(line,10)
        kk=K(k1-k2)/2*i
        points.append([K(i*i),kk])
    poly2=R.lagrange_polynomial(points)
    flag=""
    for i in poly2:
        if(i!=0 and i in poly1):
            r.sendline(str(i).encode())
            flag=r.recvline().strip().decode()
            break
    if("BKSEC" in flag):
        print(flag)
        break
    r.sendline(b"12345")
    print(r.recvline())
    r.close()
```
```
b"BKSEC{C0NGRATS!!!_Y0U'V3_F0UND_MY_ULTR4_R4R3_FL4G!!!_n3xt_t1m3_1'll_k33p_1t_4t_0_s4db1n}\n"
```
        

        


