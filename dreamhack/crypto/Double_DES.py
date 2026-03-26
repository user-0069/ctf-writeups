from pwn import *
from Crypto.Cipher import DES
io=remote("host8.dreamhack.games",16399)
print(io.recvline())
kk=io.recvline().decode().strip()
ct=kk.split(":> ")[-1]
print(ct)
dict={}
for i in range(256):
    for j in range(256):
        key=b"Dream_"+bytes([i,j])
        cipher=DES.new(key,DES.MODE_ECB)
        dict[cipher.encrypt(b"DreamHack_blocks")]=key
ct=bytes.fromhex(ct)
for i in range(256):
    for j in range(256):
        key=bytes([i,j])+b"Hacker"
        cipher=DES.new(key,DES.MODE_ECB)
        c1=cipher.decrypt(ct)
        if c1 in dict:
            cipher1=DES.new(dict[c1],DES.MODE_ECB)
            ct=cipher.encrypt(cipher1.encrypt(b"give_me_the_flag"))
            io.sendline(ct.hex().encode())
            print(io.recvline())
            #flag here, just a random hex string, nothing to show.
            break
