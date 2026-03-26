from pwn import *
from randcrack import RandCrack
rc = RandCrack()
io = remote("host8.dreamhack.games", 21569)

# verify to collect 624 outputs to reconstruct the internal state of the RNG using randcrack.
# 104*6 = 624 
for i in range(104):
    io.sendlineafter(b"> ", b"2")
    io.recvuntil(b'same: "')
    challenge_val = int(io.recvuntil(b'"', drop=True).decode())
    
    randn224 = challenge_val ^ 0xdeaddeadbeefbeefcafecafe13371337DEFACED0DEFACED0
    for j in range(6):
        part = (randn224 >> (j * 32)) & 0xffffffff
        rc.submit(part)
    #Only verify after collecting enough outputs
    if(i==103):
        io.sendlineafter(b"> ", str(challenge_val).encode())
        # verified -> can bet now
    else:
        io.sendlineafter(b"> ", str(1).encode())
    print(f"Collected: {(i+1)*6}")
# Predict all the future outputs, win all bet -> double the money each time.
money = 500
while money < 10000000000:
    io.sendlineafter(b"> ", b"1")
    predicted = rc.predict_randint(0, 0xfffffffe) % 5 + 1
    
    io.sendlineafter(b"bet", str(money).encode())
    io.sendlineafter(b"> ", str(predicted).encode())
    
    money *= 2 
    print(f"[!] Money: ${money:,}")

# get the flag 
io.sendlineafter(b"> ", b"3")
print(io.recvall().decode())
#DH{0086b1776b2b2dac7aebb790ec005ecf2bcce345c52225f03bb177b47a357a40}
