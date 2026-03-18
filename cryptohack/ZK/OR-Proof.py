#OR-proof from ZKPs challenges on Cryptohack
from sage.all import *
from pwn import *
context.log_level="debug"
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2
w0 = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y0 = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5
# w1 = REDACTED
y1 = 0x1ccda066cd9d99e0b3569699854db7c5cf8d0e0083c4af57d71bf520ea0386d67c4b8442476df42964e5ed627466db3da532f65a8ce8328ede1dd7b35b82ed617
io=remote("archive.cryptohack.org", 11840)
#first round
#(a1,e1,z1) = (1,q,0) is a valid transcript
#(a0,e0,z0) can be forged base on the above transcript
kk=io.recvuntil(b"w1").strip().decode()
kk=io.recvuntil(b"a0:")
io.sendline(b"1")
kk=io.recvuntil(b"a1:")
io.sendline(b"1")
kk=io.recvline().decode().strip()
s=int(kk.split("= ")[-1])
e1=q
e0=e1^s
z0=e0*w0
z1=0
io.sendlineafter(b"e0:",str(e0).encode())
io.sendlineafter(b"e1:",str(e1).encode())
io.sendlineafter(b"z0:",str(z0).encode())
io.sendlineafter(b"z1:",str(z1).encode())
#second round
# z0-z2 = w*(e0-e2) (mod q) -> find a valid w
kk=io.recvline().strip().decode()
kk=io.recvline().strip().decode()
y0=int(kk.split(" ")[-1])
kk=io.recvline().strip().decode()
y1=int(kk.split(" ")[-1])
kk=io.recvline().strip().decode()
io.recvline().strip().decode()
list1=[]
for i in range(7):
    kk=io.recvline().strip().decode()
    s=int(kk.split("= ")[-1])
    list1.append(s)
io.recvline().strip().decode()
list2=[]
for i in range(7):
    kk=io.recvline().strip().decode()
    s=int(kk.split("= ")[-1])
    list2.append(s)
w=0
if(list1[3]==list2[3]):
   w=(list1[6]-list2[6])*inverse_mod(list1[4]-list2[4],q)%q
else:
   w=(list1[5]-list2[5])*inverse_mod(list1[3]-list2[3],q)%q
io.sendlineafter(b"witness!",str(w).encode())
io.recvline()  
#third round
# (a0,e0,z0) = (1,0,0)
# (a1,e1,z1) = (y1^(-s),s,0)
io.recvline()
kk=io.recvline().strip().decode()
y0=int(kk.split(" ")[-1])
kk=io.recvline().strip().decode()
y1=int(kk.split(" ")[-1])
kk=io.recvline().strip().decode()
s=int(kk.split(" ")[-1])
io.sendline(b"1")
io.sendline(str(pow(y1,-s,p)).encode())
io.sendline(b"0")
io.sendline(str(s).encode())
io.sendline(b"0")
io.sendline(b"0")
io.recvline()






