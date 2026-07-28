import json
import random
import math
from Crypto.Util.number import getPrime, bytes_to_long

# ==========================================
# CHALLENGE CONFIGURATION
# ==========================================
FLAG = b"CTF{c0mm0n_m0dulu5_m33ts_lcm_br04dc4st_h4h4}"
TARGET_E = 945

# "Noise" primes to multiply (not factors of 945)
NOISE_PRIMES = [17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]

# Static padding (required)
pad_len = 255 - len(FLAG)
padded_flag = (b"\xff" * pad_len) + FLAG
m = bytes_to_long(padded_flag)

# ==========================================
# FREQUENCY DISTRIBUTION 
# ==========================================
exponents = [3, 5, 7, 9, 15, 21, 27, 35, 45, 63, 105, 135, 189, 315]
frequencies = {e: e - 1 for e in exponents}
frequencies[315] -= 15 # Force the total unique N to be exactly 945

e_list = []
for e, count in frequencies.items():
    e_list.extend([e] * count)
random.shuffle(e_list)

# ==========================================
# GENERATE DATA
# ==========================================
dataset = []
total_unique_N = len(e_list)

print(f"[*] Generating {total_unique_N} moduli N and applying Common Modulus Trick...")

for idx, base_e in enumerate(e_list):
    
    # 50% chance to apply Common Modulus trick (split 1 tuple into 2 tuples with the same N)
    use_common_modulus = random.choice([True, False])
    
    if use_common_modulus:
        # Choose 2 different noise primes
        p1, p2 = random.sample(NOISE_PRIMES, 2)
        e1 = base_e * p1
        e2 = base_e * p2
        
        # Ensure both e1 and e2 are coprime with phi(N)
        while True:
            p = getPrime(1024)
            if math.gcd(e1 * e2, p - 1) == 1:
                break
        while True:
            q = getPrime(1024)
            if math.gcd(e1 * e2, q - 1) == 1:
                break
                
        N = p * q
        c1 = pow(m, e1, N)
        c2 = pow(m, e2, N)
        
        # Add these 2 tuples to the dataset
        dataset.append({"N": hex(N), "e": e1, "c": hex(c1)})
        dataset.append({"N": hex(N), "e": e2, "c": hex(c2)})
        
    else:
        # Generate normal tuple
        while True:
            p = getPrime(1024)
            if math.gcd(base_e, p - 1) == 1:
                break
        while True:
            q = getPrime(1024)
            if math.gcd(base_e, q - 1) == 1:
                break
                
        N = p * q
        c = pow(m, base_e, N)
        dataset.append({"N": hex(N), "e": base_e, "c": hex(c)})

    if (idx + 1) % 100 == 0:
        print(f"    -> Generated {idx + 1}/{total_unique_N} logic blocks...")

# Shuffle the entire dataset so players must group N themselves
random.shuffle(dataset)

with open("challenge_data.json", "w") as f:
    json.dump(dataset, f, indent=4)
    
print(f"\n[+] Done! File has {len(dataset)} entries (including Common Modulus pairs).")
