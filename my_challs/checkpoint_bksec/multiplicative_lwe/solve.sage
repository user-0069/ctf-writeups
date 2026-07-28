from sage.all import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import ast

# ==========================================
# 1. PARSE THE CHALLENGE DATA
# ==========================================
print("[*] Loading data...")
with open("output.txt", "r") as f:
    lines = f.readlines()
    p = int(lines[0].split("=")[1].strip())
    A = ast.literal_eval(lines[1].split("=")[1].strip())
    b = ast.literal_eval(lines[2].split("=")[1].strip())
    enc_flag = bytes.fromhex(lines[3].split("=")[1].strip().strip("'"))

M = len(b)
N = len(A[0])

# ==========================================
# 2. POHLIG-HELLMAN DISCRETE LOGS 
# ==========================================
print("[*] Setting up GF(p)...")
F = GF(p)

k = F(2).multiplicative_order()
d = (p - 1) // k

print(f"[*] Target log for noise (d) = {d}")

# 1. Start with any primitive root
g_any = F.primitive_element()
X_any = discrete_log(F(2), g_any)

# 2. Find the base multiplier 'c'
c = X_any // d
q = (p - 1) // d

# 3. Find an exponent 'm' that is coprime to p-1
m = c
while gcd(m, p - 1) != 1:
    m += q

# 4. Generate the perfect primitive root
g = g_any ** m

# Verify it worked!
X = discrete_log(F(2), g)
print(f"[*] Perfect generator found!")

print(f"[*] Mapping {M * N} elements via Pohlig-Hellman...")
A_log = []
for i in range(M):
    if i % 10 == 0:
        print(f"    Mapping row {i}/{M}...")
    A_log.append([discrete_log(F(val), g) for val in A[i]])

b_log = [discrete_log(F(val), g) for val in b]

# ==========================================
# 3. LATTICE REDUCTION (ISOLATING NOISE)
# ==========================================
print("[*] Setting up LWE Lattice directly mod p-1...")

M_mat = matrix(ZZ, M, N)
v_vec = vector(ZZ, M)

for i in range(M):
    v_vec[i] = b_log[i]
    for j in range(N):
        M_mat[i, j] = A_log[i][j]

print("[*] Setting up generators...")
G = matrix(ZZ, M + N, M)

# Top block: (p-1) * I_M
for i in range(M):
    G[i, i] = p - 1
    
# Bottom block: Transpose of M_mat
for i in range(N):
    for j in range(M):
        G[M + i, j] = M_mat[j, i]

print("[*] Reducing basis via Hermite Normal Form...")
B = G.hermite_form()[:M, :]

print("[*] Applying Kannan's Embedding...")
Z = matrix(ZZ, M + 1, M + 1)

for i in range(M):
    for j in range(M):
        Z[i, j] = B[i, j]
        
for j in range(M):
    Z[M, j] = v_vec[j]
    
Z[M, M] = 1 

print("[*] Running LLL...")
L = Z.LLL()

noise = None
for row in L:
    if abs(row[-1]) == 1:
        # The noise values in the lattice are now exactly 0 or d
        if all(abs(val) <= d for val in row[:-1]):
            multiplier = -1 if row[-1] == 1 else 1
            # Divide by d to get back the binary 0/1 array for the next step!
            noise = [(val * multiplier) // d for val in row[:-1]]
            break

if noise is None:
    print("[-] Lattice failed to find the noise vector.")
    exit()

print(f"[+] Binary noise vector recovered: {noise[:15]}...")

# ==========================================
# 4. RECOVER SECRET & DECRYPT (Smith Normal Form)
# ==========================================
print("[*] Solving noiseless system using Smith Normal Form...")

target_ZZ = vector(ZZ, M)
for i in range(M):
    # noise[i] is 0 or -1. abs() forces it to 0 or 1.
    # Multiply by d to reconstruct the exact added noise e_i.
    clean_val = b_log[i] - (d * abs(noise[i]))
    target_ZZ[i] = int(clean_val % (p - 1))

A_ZZ = matrix(ZZ, M, N)
for i in range(M):
    for j in range(N):
        A_ZZ[i, j] = int(A_log[i][j])

# Decompose A into U * A * V = D
# This gives A = U^-1 * D * V^-1
print("[*] Computing SNF decomposition...")
D, U, V = A_ZZ.smith_form()

# We want A * s = target (mod p-1)
# Which becomes D * (V^-1 * s) = U * target (mod p-1)
U_target = (U * target_ZZ) % (p - 1)
y = vector(ZZ, N)

print("[*] Solving independent diagonal equations...")
for i in range(N):
    d_val = int(D[i, i])
    t_val = int(U_target[i])
    
    if d_val == 0:
        continue
        
    # Safely solve d_val * y[i] == t_val mod (p-1) by dividing out the GCD
    g = gcd(d_val, p - 1)
    modulus = (p - 1) // g
    
    inv = inverse_mod(d_val // g, modulus)
    y[i] = ((t_val // g) * inv) % modulus

# Map y back to the original secret space: s = V * y
s_recovered = (V * y) % (p - 1)
s_recovered = [int(val) for val in s_recovered]

print(f"[+] Secret s recovered: {s_recovered[:5]}...")

print("[*] Decrypting flag...")
key = hashlib.sha256(str(s_recovered).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
try:
    decrypted = unpad(cipher.decrypt(enc_flag), 16)
    print(f"\nFLAG: {decrypted.decode()}")
except ValueError:
    print("[-] Decryption failed. Incorrect secret.")
