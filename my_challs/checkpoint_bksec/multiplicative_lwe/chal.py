import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secret import FLAG  

N = 90
M = 110

p = 1507732800615963885673959670754376244906477745307148597385586495296560566762388376487051649046491050109247411649642940750541387415484523419049959869647
s = [random.randint(2, p - 1) for _ in range(N)]


# CUSTOM ALGEBRAIC STRUCTURE
def add(x, y):
    """Vector addition is defined as modular multiplication."""
    return (x * y) % p

def mul(scalar, x):
    """Scalar multiplication is defined as modular exponentiation."""
    return pow(x, scalar, p)

def custom_dot_product(vec_A, vec_s):
    """Computes A • s using the custom algebra."""
    result = 1  # 1 is the identity element (zero)
    for a, sec in zip(vec_A, vec_s):
        term = mul(sec, a)
        result = add(result, term)
    return result

# PUBLIC KEY GENERATION
def generate_public_key():
    A = []
    b = []
    
    for _ in range(M):
        A_i = [random.randint(2, p - 1) for _ in range(N)]
        
        # Calculate A • s
        dot_product = custom_dot_product(A_i, s)
        
        # Add noise e. 
        # In our algebra, 1 acts as '0' (no noise) and 2 acts as '1' (noise)
        e = random.choice([1, 2])
        b_i = add(dot_product, e)
        
        A.append(A_i)
        b.append(b_i)
        
    return A, b

if __name__ == "__main__":
    A, b = generate_public_key()
    
    # Encrypt the flag using the secret vector
    key = hashlib.sha256(str(s).encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_flag = cipher.encrypt(pad(FLAG.encode(), 16))
    
    with open("output.txt", "w") as f:
        f.write(f"p = {p}\n")
        f.write(f"A = {A}\n")
        f.write(f"b = {b}\n")
        f.write(f"enc_flag = '{encrypted_flag.hex()}'\n")
