## Description
[server.sage](https://training.bksec.vn/apiv2/files/local/9_IVJnS5GVLe9J_w2ZAzK?iat=1770887400&sig=HLXxw7KbdqEksDzXjqoYym0gyny0JroRxB7ncGaAPAQ)\
`nc 103.77.175.40 7901`
## My solution
The main problem here is to find k%3 with given 2 5x5 matrix $A$ and $A^k$ in Galois Field $GF(p)$ (i.e everything in modulo p) and solve it 20 times.
It looks like a DLP problem, but with matrix :DD. Lets analyze $p$ first.
```
p=1719620105458406433483340568317543019584575635895742560438771105058321655238562613083979651479555788009994557822024565226932906295208262756822275663694111
print(Integer(p-1).factor())
```
Ah, smooth enough:
```
2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29 * 31 * 37 * 41 * 43 * 47 * 53 * 59 * 61 * 67 * 71 * 73 * 79 * 83 * 89 * 97 * 101 * 103 * 107 * 109 * 113 * 127 * 131 * 137 * 139 * 149 * 151 * 157 * 163 * 167 * 173 * 179 * 181 * 191 * 193 * 197 * 199 * 211 * 223 * 227 * 229 * 233 * 239 * 241 * 251 * 257 * 263 * 269 * 271 * 277 * 281 * 283 * 293 * 307 * 311 * 313 * 317 * 331 * 337 * 347 * 349 * 353 * 359 * 367 * 373 * 379
```
Ok then $p-1$ is a smooth number, suitable with DLP, but A is matrix? The trick is to focus on $\det(A)$ : $\det(A^k) = \det(A)^k$.
Yes, if we get $x=\det(A)$, then we will be solving normal DLP knowing $x$ and $x^k$ (eventhough it is not guaranteed to have solutions all the time).
```

p=1719620105458406433483340568317543019584575635895742560438771105058321655238562613083979651479555788009994557822024565226932906295208262756822275663694111
r= remote("103.77.175.40", 7901)
kk=r.recvline().strip().decode()
kk=r.recvline().strip().decode()
M=kk.split(": ")[3]
M=ast.literal_eval(M)
M=matrix(GF(p),5,5,M)
detM=M.determinant()
for i in range(20):
    kk=r.recvline().strip().decode()
    print(kk)
    kk=r.recvline().strip().decode()
    N=kk.split("=")[1]
    N=ast.literal_eval(N)
    N=matrix(GF(p),5,5,N)
    detN=N.determinant()
    k=discrete_log(detN, detM, ord=Integer(p-1))
    k=k%3
    if k==0:
        k=3
    r.recvuntil(b"(1-3): ")
    r.sendline("{}".format(str(k)).encode())
kk=r.recvline().strip().decode()
print(kk)
```
It may fail with some small chance, like $\det(A) \equiv 0 \pmod{p}$ (almost never) and order of $\det(A)$ is not divided by 3.
```
[junchannn]: Wow! You might become prospective member of BKSEC! Here is your flag: BKSEC{b9d3a4f878c65ccff4294e8e83f1a281c349d1af9aebacdc48fb630cbdc5f77a}
```


