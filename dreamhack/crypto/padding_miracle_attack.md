## Description
[challenge](https://dreamhack.io/wargame/challenges/1122)
## Solution
We actually can recover the hidden IV: send plaintext `'00'*16`, the resulting first block is exactly E(IV). Use padding oracle to find IV = D(E(IV)) where E(IV) is known. With IV in hand, normal
padding oracle would help us to recover P1 from C1.
```
from pwn import *
#context.log_level = 'debug'
io=remote('host8.dreamhack.games', 9089)
io.sendlineafter(': ',b'1')
io.sendlineafter(': ',b'00'*16)
E_iv=io.recvline().strip().split(b'=> ')[-1]
print(len(E_iv))
E_iv=E_iv[:32]
I=[0]*16
forge_iv=[0]*16
for i in reversed(range(16)):
    val_pad=16-i 
    for j in range(i+1,16):
        forge_iv[j]=I[j]^val_pad
    for j in range(0,256):
        forge_iv[i]=j
        io.sendlineafter(': ',b'2')
        io.sendlineafter(': ',bytes(forge_iv).hex().encode()+E_iv)
        res=io.recvline().strip()
        if b'steal' in res:
            I[i]=j^val_pad
            print(f"Found byte {i}: {j^val_pad} when j is {j}")
            break
io.sendlineafter(': ',b'1')
io.sendlineafter(': ',b'secret')
ct=io.recvline().strip().split(b'=> ')[-1]
c1=ct[:32]
iv=I
I=[0]*16
forge_iv=[0]*16
for i in reversed(range(16)):
    val_pad=16-i 
    for j in range(i+1,16):
        forge_iv[j]=I[j]^val_pad
    for j in range(0,256):
        forge_iv[i]=j
        io.sendlineafter(': ',b'2')
        io.sendlineafter(': ',bytes(forge_iv).hex().encode()+c1)
        res=io.recvline().strip()
        if b'steal' in res:
            I[i]=j^val_pad
            print(f"Found byte {i}: {j^val_pad} when j is {j}")
            break
p1=[I[i]^iv[i] for i in range(16)]
io.sendlineafter(': ',b'3')
io.sendlineafter(': ',bytes(p1).hex().encode())
print(io.recvline().strip())


```
```
DH{Can_you_do_it_even_faster??}
```
