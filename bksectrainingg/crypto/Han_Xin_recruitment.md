## Description
`nc 103.77.175.40 7011`\
[chall.py](https://training.bksec.vn/apiv2/files/local/P9CZUEu9gsYZDXMRi5FLc?iat=1770628200&sig=JH8NOF7qVqcVazNha3O3HXXlFZZGaCfOQqTzDjwLnU0)
## My solution
Note that e=5 for every request we make, maybe we should use Hastad's Broadcast Attack. Take 5 different $(c_i,n_i)$ from the server. 
Turn this into a CRT problem: find $m^5$ such that $m^5 \equiv c_i \quad mod(n_i) \forall i$. Denote $\prod n_i = N$. The result we get
is $m^5 \quad mod(N)$, which is actually $m^5$ itself because $m^5<N$.
```
cs=[]
ns=[]
for i in range(5):
    r.recvuntil(b"(y/n) ")
    r.sendline(b"y")
    data = recv()
    c=data['requirement']
    c=int(c,16)
    n=data['key'][0]
    n=int(n,16)
    cs.append(c)
    ns.append(n)
res=crt(cs,ns)
m=iroot(res,5)
print(long_to_bytes(m[0]))
```
```
b'BKSEC{100c4ad2391728c16addcc7fb48656c8a7e1d68b615866da0f07359eba80dacf}'
```
