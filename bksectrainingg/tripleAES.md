## Description
[chall](https://training.bksec.vn/apiv2/files/local/MLD2tNXL1G9paMFp6FL3D?iat=1770538200&sig=R3uArngdfFORRtMH4Q1YQghdAArNDSdaWW-vDToUiXw)\
`nc 103.77.175.40 7021`
## My solution
The TripleAES function in the source code works as: $E3_{ijk}()=E_i() \longrightarrow E_j() \longrightarrow D_k()$\
If $D_j() = E_j()$ somehow, then we can construct $D3_{ijk}()=E_k() \longrightarrow E_j() \longrightarrow D_i()$ in order to reverse 
exactly the function E3_{ijk}().\
I repeatly `get secret` until [i,j,k] has j in [3,4,6,7] (which means D_j()=E_j()). I send the exact ciphertext and mode [k,j,i] to grab the flag.
```
while True:
    kk=r.recvuntil(b"Quit").decode()
    r.sendline(b"2")
    kk=r.recvuntil(b"]").decode()
    list=kk.split("\n")
    text=list[1].split(" ")[-1]
    iv=list[2].split(" ")[-1]
    mode=list[3].split("= ")[-1]
    mode=ast.literal_eval(mode)
    mode=[int(x) for x in mode]
    if(mode[1] in [3,4,6,7]):
        break
kk=r.recvuntil(b"Quit").decode()
r.sendline(b"1")
kk=r.recvuntil(b"OFB\n").decode()
to_send=str(mode[2])+" "+str(mode[1])+" "+str(mode[0])
r.sendline(to_send.encode())
kk=r.recvuntil(b"None: ").decode()

r.sendline(iv.encode())
kk=r.recvuntil(b": ").decode()
r.sendline(text.encode())
kk=r.recvuntil(b"]")
print(kk.decode())
lines=kk.decode().split("\n")
flag=lines[-2].split("= ")[-1]
print(flag)
flag=bytes.fromhex(flag)
print(flag)
```
```
b'BKSEC{44d4e9a1f5647449ef521d70152c08571c8d17392c751bb163a8bf124ba52c8d}\t\t\t\t\t\t\t\t\t\xf7\xebf!vN\xa8<\xebX"\x1bQ\x10\x875'
```
