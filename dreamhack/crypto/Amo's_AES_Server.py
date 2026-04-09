from gmpy2 import iroot
from sage.all import crt,gcd,inverse_mod
from Crypto.Util.number import *
from pwn import *
context.log_level='debug'
io=remote("host3.dreamhack.games",8344)
#Denote D() as real AES block decryption
#Denote E() as real AES block encryption
#remember that this problem enc and dec is reversed
#please draw the picture of AES by yourself to understand the process
def get_enc():
    #get flag_enc
    print(io.recvuntil(b"Flag\n"))
    io.sendline(b"3")
    enc=io.recvline().strip().decode().split("= ")[-1]
    return enc
def get_iv():
    io.recvuntil(b"Flag\n")
    io.sendline(b"2")
    io.sendlineafter(b": ",b"00"*16) #send 00..00 to get E(IV)
    eiv=io.recvline().strip().decode() 
    io.recvuntil(b"Flag\n")
    io.sendline(b"1")
    io.sendlineafter(b": ",b"00"*16+eiv.encode()) #send 00..00||E(IV) to get D(E(IV))=IV
    kk=io.recvline().strip().decode()
    iv=kk[32:]
    return iv
def get_block(iv,p1,c2):
    io.recvuntil(b"Flag\n")
    io.sendline(b"1")
    io.sendlineafter(b": ",b"00"*16) #send 00..00 to get D(00..00)^IV
    kk=io.recvline().strip().decode()
    d_0_iv=kk[:32]
    io.recvuntil(b"Flag\n")
    io.sendline(b"2")
    dp2=xor(bytes.fromhex(c2),bytes.fromhex(p1)) #get D(p2)
    io.sendlineafter(b": ",d_0_iv.encode()+dp2.hex().encode()) #send D(00..00)^IV||D(p2) to get E(D(p2)) = p2
    kk=io.recvline().strip().decode()
    return kk[32:]
enc=get_enc()
c=[enc[i:i+32] for i in range(0,len(enc),32)]
iv=get_iv()
print(iv)
p=["0" for i in range(0,4)] 
p[0]=iv
for i in range(1,4):
    #find plaintext block by block note that p is 1-indexed, c is 0-indexed, p[0] corresponds to iv
    p[i]=get_block(iv,p[i-1],c[i-1])
print(bytes.fromhex("".join(p[1:])))
#DH{435_C8C_1V:iaAJx2r6Dsf6t8xh0WyEcw==}\n\x08\x08\x08\x08\x08\x08\x08\x08


