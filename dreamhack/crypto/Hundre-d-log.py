from pwn import *
import random as py_random
from Crypto.Util.number import getPrime, isPrime
from sage.all import GF, discrete_log, primitive_root

# create a big prime p just under 2^512 so that secret is always smaller than p
def get_high_ceiling_smooth_prime():
    print("[*] Đang rèn High-Ceiling Smooth Prime (Bám trần 2^512)...")
    primes_16 = [getPrime(16) for _ in range(100)]
    
    while True:
        B = 2
        #smooth 480-bit B
        while B.bit_length() < 480:
            B *= py_random.choice(primes_16)
        
        # find a prime in form B*M + 1 
        # M is small so B*M is still smooth
        target = (2**512 - 1)
        M_start = target // B
        
        
        for i in range(1000):
            M = M_start - i
            cur = B * M
            p = cur + 1
            
            if isPrime(p) and p.bit_length() == 512:
                return p

p = get_high_ceiling_smooth_prime()
# primitive_root for unique DLP solution
g = int(primitive_root(p))

io = remote('host8.dreamhack.games', 12659)
io.sendlineafter(b'Prime: ', str(p).encode())
io.sendlineafter(b'g: ', str(g).encode())

# GF to run in sage
F = GF(p)
base_g = F(g)

for rnd in range(100):
    io.recvuntil(b'--- Round')
    io.recvline() 
    
    line = io.recvline().decode().strip()
    k_val = int(line.split(" = ")[1])
    
    
    # DLP
    secret = int(discrete_log(F(k_val), base_g))
    
    io.sendlineafter(b'secret: ', str(secret).encode())


print(io.recvall().decode())
#DH{Try_making_other_kinds_of_smooth_prime_number_too}
