
## Challenge Overview
The server implements a non-interactive Zero-Knowledge Proof (ZKP) for a Hamiltonian Cycle using Pedersen commitments and the Fiat-Shamir heuristic to simulate 128 rounds of challenges. 

We are given a graph $G$ that **does not** have a Hamiltonian cycle. To get the flag, we have to fool the verifier into accepting our proof for 128 consecutive rounds by abusing flaws in the Fiat-Shamir implementation and the verifier's logic.

---

## The Vulnerabilities

A secure ZKP requires strict enforcement of cryptographic properties (Binding, Hiding, Soundness). The provided verifier fails on almost all fronts. Here are all the vulnerabilities present in the code:

### 1. Insecure Serialization in Fiat-Shamir (The Core Flaw)
When generating the Fiat-Shamir state, the server flattens the 2D matrix into a string using `"".join()` without any delimiters:
```python
first_message = "".join([str(x) for xs in G for x in xs])
```
Because there are no commas or brackets in the resulting string, arrays like `[12, 3]` and `[1, 23]` both serialize to `"123"`. This allows us to craft two completely different matrices ($A_0$ and $A_1$) that hash to the exact same state.

### 2. Lack of Pedersen Bounds Checking
The verifier never checks if our commitments are within the group $\bmod P$. It simply evaluates:
```python
(commitment * pow(h1, -message, P) * pow(h2, -r, P) ) % P == 1
```
Because of the modulo operation at the very end, we can submit massive integers that are far larger than $P$. As long as $C \equiv \text{validcommit} \pmod P$, the server accepts it.

### 3. Partial Verification in Challenge 1
During Challenge 1 (proving the cycle), the server iterates through our provided 5 edges and checks that they open to $1$. **It completely ignores the other 20 elements in the matrix.** Because they are never passed to the verification math, those elements can be arbitrary garbage.

### 4. Permutation Collapse (Challenge 0 Logic Flaw)
During Challenge 0, we must provide a permutation of the graph. The server applies our permutation and expects the resulting matrix to match our openings. However, if we submit a permutation array of `[1, 1, 1, 1, 1]`, the server's mapping collapses the entire graph into a single node. The final value gets overwritten to $0$, resulting in a completely empty $5 \times 5$ matrix of $0$ s. This allows us to pass Challenge 0 using a matrix entirely committed to $0$.


---

## The Exploit Strategy: The Pure Math Approach

Instead of relying on JSON string type-confusion, we can exploit vulnerabilities 1, 2, and 4 mathematically. 

Our goal is to create two matrices, $A_0$ (for Challenge 0) and $A_1$ (for Challenge 1) such that:
1. $A_0$ passes Challenge 0 (all cells open to `0`).
2. $A_1$ passes Challenge 1 (the 5 cycle cells open to `1`, the rest don't matter).
3. The string representation of $A_0$ is identical to $A_1$, forcing the Fiat-Shamir hash to remain identical regardless of which payload we send.

To simplify the math, we reuse a static random value $r$ for all our commitments. 
Let $C_0 = \text{Commit}(0, r)$ and $C_1 = \text{Commit}(1, r)$.

### The String Shift
We need an index in $A_0$ to open to `0`, but visually look like $C_1$ in the serialized string.
Using the lack of bounds checking, we can craft a massive integer: $C_1 \cdot 10^d + M$.
For this to open to `0`, it must be congruent to $C_0 \pmod P$:
$$C_1 \cdot 10^d + M \equiv C_0 \pmod P$$
$$M \equiv C_0 - C_1 \cdot 10^d \pmod P$$

By iterating $d$, we find a padding value $M$ where the length of $M$ as a string exactly matches $d$. 

Now we construct the matrices:
* **In $A_0$:** At the target index, we place the massive integer $C_1 \cdot 10^d + M$. When evaluated $\bmod P$, it collapses back to $C_0$ and successfully opens to `0`.
* **In $A_1$:** At the target index, we place $C_1$. At the *next* index, we place $M$, shifted left by the length of $C_0$ so that it seamlessly concatenates with the next cell. 

Because `"".join()` strips the array boundaries, the text output of both matrices is **100% identical**. 

Since the strings match, we can simulate the server's Fiat-Shamir state locally, predict all 128 challenge bits perfectly, and feed the server the correct matrix for every round!

---

## The Exploit Code

```python
from sage.all import *
from hamiltonicity import *
from pwn import *
import json
#context.log_level ="debug"
io=remote("archive.cryptohack.org", 34597)
def send_json(data):
    io.sendline(json.dumps(data).encode())
def recv_json():
    return json.loads(io.recvline().decode())
numrounds=128
G = [
        [0,0,1,0,0],
        [1,0,0,0,0],
        [0,0,0,1,0],
        [0,0,0,0,1],
        [0,1,0,0,0]
    ]
indices = [2,5,13,19,21]
cycle = [[0,2],[2,3],[3,4],[4,1],[1,0]]
fixed_r=random.randint(0,q)
def my_pederson_commit(message, pedersen_params = comm_params):
    P,q,h1,h2 = pedersen_params
    r = fixed_r
    commitment = (pow(h1,message,P) * pow(h2,r,P)) % P
    return commitment, r
C1,_=my_pederson_commit(1)
C0,_=my_pederson_commit(0)
d=0
M=0
while(True):
    M=(C0-C1*(10**d))%P
    if(len(str(M))==d):
        break
    d+=1
    if(d>10000):
        print("[-] Failed to find M")
        exit(1)
print(f"[*] Found M = {M} with d = {d}")
A0=[C0]*25
for i in indices:
    A0[i]=C1*(10**d)+M
A1=[C0]*25
for i in indices:
    A1[i]=C1
    A1[i+1]=M*(10**len(str(C0)))+C0
A_0 = [A0[i*5:(i+1)*5] for i in range(5)]
A_1 = [A1[i*5:(i+1)*5] for i in range(5)]
A0=A_0
A1=A_1
a0string = "".join([str(x) for xs in A0 for x in xs])
a1string = "".join([str(x) for xs in A1 for x in xs])
assert a0string==a1string
state=b""
for i in range(numrounds):
    state=hash_committed_graph(A0,state,comm_params)
chall_bits = bin(int.from_bytes(state, 'big'))[-numrounds:]
io.recvuntil(b"cycle!\n")
print(chall_bits)

for i in range(numrounds):
    io.recvuntil(b"proof: ")
    if int(chall_bits[i])==0:
        to_send={
            "A": A0,
            "z": ([1,1,1,1,1],[[[0,fixed_r]]*5]*5)
        }
    else:
        to_send={
            "A": A1,
            "z": (cycle,[fixed_r]*5)
        }
    send_json(to_send)
print(io.recvall())


```
