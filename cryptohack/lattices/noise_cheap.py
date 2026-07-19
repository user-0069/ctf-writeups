from sage.all import *
from pwn import *
from ast import literal_eval
import json

io = remote("socket.cryptohack.org", 13413)

n = 64
p = 257
q = 1048583

def send_json(data):
    io.sendline(json.dumps(data).encode())

def recv_json():
    return json.loads(io.recvline().decode())

io.recvline()
to_send = {"option":"encrypt","message":"0"}
As = []
bs = []
#the idea is to send m=0, so that the equation becomes b = A*S + p*e, and we can recover e using LLL
#tre trick is to divide both side by p in mod q, so the e is a small vector like Bounded noise challenge
num_samples = 130
for i in range(num_samples):
    send_json(to_send)
    kk = recv_json()
    As.append(literal_eval(kk["A"]))
    bs.append(int(kk["b"]))
    print(f"Received data for iteration {i}")

print("[*] Scaling and building lattice...")
p_inv = inverse_mod(p, q)

A_Fq = Matrix(GF(q), num_samples, n, As)
B_Fq = Matrix(GF(q), 1, num_samples, bs)

A_prime = (A_Fq * p_inv).change_ring(ZZ).transpose()
B_prime = (B_Fq * p_inv).change_ring(ZZ)
Q = identity_matrix(ZZ, num_samples) * q

M = block_matrix([
    [zero_matrix(ZZ, n, 1), A_prime],
    [matrix(ZZ, 1, 1, [1]), B_prime],
    [zero_matrix(ZZ, num_samples, 1), Q]
])

print("[*] Running LLL...")
V = M.LLL() 

print("[*] Finding Error vector E...")
E = None
for row in V:
    if abs(row[0]) == 1:
        valid = True
        for val in row[1:]:
            if abs(val) > 1: 
                valid = False
                break
        
        if valid:
            if row[0] == 1:
                E = row[1:]
            else:
                E = -row[1:]
            break

if E is None:
    print("[-] LLL failed to find E")
    exit(0)

print("[+] Recovered Error Vector E!")

print("[*] Solving for S...")
E_vec = vector(GF(q), E)
b_vec = vector(GF(q), bs)

b_minus_pE = b_vec - p * E_vec

S = A_Fq.solve_right(b_minus_pE)
print("[+] S recovered successfully!")

S_ZZ = vector(ZZ, S)
res = ""

print("[*] Decrypting Flag...")
for i in range(46):
    to_send = {"option":"get_flag","index":str(i)}
    send_json(to_send)
    kk = recv_json()
    if("A" not in kk):
        print("[-] No more data received. Exiting.")
        break
    A_vec = vector(ZZ, literal_eval(kk["A"]))
    b_val = ZZ(kk["b"])
    
    val = (b_val - A_vec * S_ZZ) % q
    if val > q // 2:
        val -= q
    
    m = val % p
    res += chr(int(m))

print("\n[+] FLAG:", res)
