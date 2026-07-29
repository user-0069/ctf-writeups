import json
import math
from Crypto.Util.number import long_to_bytes
import gmpy2


def egcd(a, b):
    """Extended Euclidean Algorithm: Returns (gcd, x, y) such that a*x + b*y = gcd"""
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def mod_pow_neg(base, exp, mod):
    """Modular exponentiation with support for negative exponents"""
    if exp < 0:
        # If the exponent is negative, we must first find the modular inverse of the base
        base = pow(base, -1, mod)
        exp = -exp
    return pow(base, exp, mod)


def solve():
    print("[*] Reading data from challenge_data.json...")
    with open("challenge_data.json", "r") as f:
        data = json.load(f)

    
    grouped_data = {}
    for item in data:
        N = int(item["N"], 16)
        e = int(item["e"])
        c = int(item["c"], 16)
        
        if N not in grouped_data:
            grouped_data[N] = []
        grouped_data[N].append((e, c))

    print(f"[*] Parsed {len(data)} tuples, found {len(grouped_data)} unique moduli N.")

    clean_tuples = []
    
    print("[*] Phase 1: Common Modulus Decryption (supports n-tuples)...")
    for N, items in grouped_data.items():
        current_e, current_c = items[0]
        
        for next_e, next_c in items[1:]:
            # Solve Bézout's identity: current_e * u + next_e * v = gcd(current_e, next_e)
            g, u, v = egcd(current_e, next_e)
            
            c1_u = mod_pow_neg(current_c, u, N)
            c2_v = mod_pow_neg(next_c, v, N)
            
            # Update base (e, c) to the newly combined value
            current_c = (c1_u * c2_v) % N
            current_e = g
            
        clean_tuples.append((N, current_e, current_c))

    print(f"[*] Phase 1 Complete. Extracted into {len(clean_tuples)} base tuples.")

    
    # Calculate the Least Common Multiple (LCM) of all e's to use as the Target E
    TARGET_E = 1
    for _, e, _ in clean_tuples:
        TARGET_E = math.lcm(TARGET_E, e)
        
    print(f"[*] Phase 2: Automatically calculated TARGET_E = {TARGET_E}. Synchronizing exponents...")
    
    C_list = []
    N_list = []
    
    for N, e, c in clean_tuples:
        multiplier = TARGET_E // e
        c_pushed = pow(c, multiplier, N)
        
        C_list.append(c_pushed)
        N_list.append(N)

   #hastad broadcast attack
    print("[*] Phase 3: Calculating CRT... (may take a few seconds)")
    N_tot = 1
    for n in N_list:
        N_tot *= n

    C_tot = 0
    for c, n in zip(C_list, N_list):
        m_i = N_tot // n
        y = pow(m_i, -1, n)
        C_tot = (C_tot + c * m_i * y) % N_tot

    print(f"[*] CRT Complete. Calculating {TARGET_E}-th root...")
    
    m, is_exact = gmpy2.iroot(C_tot, TARGET_E)
    
    if is_exact:
        print("[+] Valid root found! Unpadding data...")
        msg = long_to_bytes(int(m))
        print(f"\nFLAG : {msg}")
    else:
        print("[-] An error occurred, root is not an integer. The data might be insufficient or the CRT calculation is incorrect.")

if __name__ == "__main__":
    solve()
