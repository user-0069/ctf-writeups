## Description
[chall.py](https://training.bksec.vn/apiv2/files/local/Clv_4oI0sy-RoYr6l1fUt?iat=1771342200&sig=nWSk7pw9csa203fxZ1RsVklCJfJd9TzYBtdz4M8H_uE)\
`nc 103.77.175.40 7301`
## My solution
There only $10^6$ possible key in this problem, so we can bruteforce $a,b$ to see if the decrypted ciphertext give us the plaintext we sent.
To avoid nested loop which is time consuming, we can use set.
```
r=remote("103.77.175.40", 7301)
line = r.recvline().strip().decode()
print(line)
c=line.split(" ")[-1]
c=bytes.fromhex(c)
print(c)
line=r.recvline().strip()
print(line)
r.recvuntil(b">> ")
r.sendline(b"1")
line=r.recvline().strip().decode()
print(line)
cc=line.split(" ")[-1]
cc=bytes.fromhex(cc)
line=r.recvline().strip()
print(line)
r.close()
s=set()
a,b=0,0
for i in range(0,999999):
    key=(str(i).zfill(6).encode()*4)[:16]
    s.add(encrypt(b"1",key))
for i in range(0,999999):
    key=(str(i).zfill(6).encode()*4)[:16]
    cc1=decrypt(cc,key)
    if cc1 in s:
        b=i
        for j in range(0,999999):
            key=(str(j).zfill(6).encode()*4)[:16]
            if decrypt(cc1,key) ==pad(b"1",16):
                a=j
                break
        break
print(a,b)
c=decrypt(c,(str(b).zfill(6).encode()*4)[:16])
c=decrypt(c,(str(a).zfill(6).encode()*4)[:16])
print(c)
```
```
b'BKSEC{Bl0ck_c1ph3r_1s_s0000_c0n7us1n99!!!}\x06\x06\x06\x06\x06\x06'
```
