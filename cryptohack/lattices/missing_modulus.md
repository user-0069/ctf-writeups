## Vulnerability Analysis

The challenge attempts to implement a Learning with Errors (LWE) encryption scheme, but it contains a fatal implementation flaw in the `encrypt` function:

```python
b = A @ S + m * delta + e
```

**The Bug:** The author forgot to apply the ciphertext modulus reduction (`% q`). 

In a correct LWE implementation, the modulo operation wraps the values, breaking the direct linear relationship and making it an NP-Hard problem (requiring Lattice reduction to solve). Without `% q`, the equation is no longer cryptographic. It becomes a standard overdetermined system of linear equations over the real/integer numbers, with a slight Gaussian noise ($e$).

## Exploitation Strategy

1.  **Data Collection:** Query the `encrypt` oracle with $m = 0$ to collect a system of equations: $b = A \cdot S + e$. Since the secret vector $S$ has a dimension of 512, we need slightly more than 512 samples (e.g., 600) to account for the noise $e$ and prevent an underdetermined system.
2.  **Secret Recovery:** Solve the overdetermined system. We can do this either via Data Science techniques (Least Squares Regression) or Lattice Reduction (LLL).
3.  **Decryption:** Once $S$ is known, query the server for each flag character. Since $b = A \cdot S + m \cdot \Delta + e$, we can isolate the message: $m = \text{round}((b - A \cdot S) / \Delta)$. The round function completely absorbs the small noise $e$.

---

## Solution 1: Linear Regression 
This uses `numpy.linalg.lstsq` to average out the Gaussian noise and find the exact integer array $S$ in less than a second. 

```python
#!/usr/bin/env python3
from pwn import remote
from ast import literal_eval
import numpy as np
import json

io = remote("socket.cryptohack.org", 13412)
io.recvline()

n = 512
p = 257
q = 6007
delta = int(round(q/p))

def send_json(data):
    io.sendline(json.dumps(data).encode())

def recv_json():
    return json.loads(io.recvline().decode())

# Step 1: Collect 600 samples (Must be > 512 to avoid underdetermined system)
As, bs = [], []
to_send = {"option": "encrypt", "message": "0"}

print("[*] Collecting 600 samples...")
for _ in range(600):
    send_json(to_send)
    data = recv_json()
    As.append(literal_eval(data["A"]))
    bs.append(int(data["b"]))

# Step 2: Solve via Least Squares and round to nearest integer
print("[*] Solving linear regression...")
S_approx = np.linalg.lstsq(As, bs, rcond=None)[0]
S = np.round(S_approx)

# Step 3: Decrypt the flag
print("[*] Recovering flag...")
flag = ""
for i in range(46):
    send_json({"option": "get_flag", "index": str(i)})
    data = recv_json()
    A = literal_eval(data["A"])
    b = int(data["b"])
    
    # Isolate m*delta + e, then divide by delta and round
    m_delta_e = b - np.dot(S, A)
    m = round(m_delta_e / delta)
    flag += chr(m)

print(f"\n[+] Flag: {flag}")
```

---

## Solution 2: Lattice 
We can send m=0 multiple times and solve it like *Nativity* and *Bounded noise* challenge.
