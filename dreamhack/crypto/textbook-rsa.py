from pwn import *
from sage.all import *
from Crypto.Util.number import long_to_bytes
import ast
context.log_level="debug"
io=remote("host8.dreamhack.games", 18723)
kk=io.recvline().decode().strip()
print(kk)
io.recvuntil("info\n")
io.sendline(b"3")
N=int(io.recvline().decode().strip().split(":")[1])
e=int(io.recvline().decode().strip().split(":")[1])
c=int(io.recvline().decode().strip().split(":")[1])
io.recvuntil("info\n")
io.sendline(b"2")
# cannot send c? just send -c !!!
io.sendlineafter(b": ",long_to_bytes(N-c).hex().encode())
kk=io.recvline().decode().strip()
pt=N-int(kk)
print(long_to_bytes(pt))
