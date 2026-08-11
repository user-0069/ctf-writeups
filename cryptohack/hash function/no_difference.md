
## 1. The Target Overview
The challenge provides a custom Substitution-Permutation Network (SPN) hash function. The state size is 8 bytes, initialized to a fixed value. 

Data is injected in 4-byte blocks, XORed into the **last 4 bytes** of the 8-byte state. The state then passes through a `permute()` function and a `substitute()` S-box function. After all data blocks are injected, the state runs through 16 deterministic mixing rounds.

Our goal is to find a hash collision: two different messages that produce the exact same final hash.

## 2. The Vulnerability: The `0xdf` S-box Flaw
Analyzing the provided `SBOX`, we can observe a critical structural flaw. The S-box maps multiple inputs to the exact same output. Specifically:
`SBOX[x] == SBOX[x ^ 0xdf]`

If we can introduce a difference of exactly `0xdf` (or `0x00`) across all 8 bytes of the state right before it enters the `substitute()` function, the S-box will completely absorb the difference. The states will collide, and the remaining 16 rounds will process identically.

## 3. The Mathematical Trap (Why a 1-block `0xdf` attack fails)
A naive approach is to inject a 4-byte block that perfectly aligns with the `0xdf` difference in the very first round. However, this is mathematically impossible due to how `permute()` operates.

The `permute()` function acts as an $8 \times 8$ bit-matrix transpose. It takes the $i$-th bit of every input byte and maps them to the $i$-th output byte. 

Because we only control the last 4 bytes of the state, our input difference is strictly forced to be:
`[0x00, 0x00, 0x00, 0x00, d0, d1, d2, d3]`

Since the first 4 bytes are zeroes, the top 4 rows of our bit-matrix are zero. After the transpose, the **lowest 4 bits** of every single output byte are mathematically forced to be `0`. 
Because `0xdf` in binary is `11011111` (which requires `1`s in the lowest bits), the permutation can *never* output a `0xdf` difference from a 4-byte injection.

## 4. The Solution: A 2-Block Differential Attack
To bypass the bit-transpose trap, we push the collision to the **second round**. By letting the first block pass through the first round's S-box, the state is heavily scrambled, bypassing the strict `0x00` constraints on the first 4 bytes. 

We can achieve this using a 2-block (8-byte) differential attack:

### Phase 1: The Truncated Dictionary Attack (Block 1)
We need a difference *before* the second round's permutation that will result in a `0xdf`/`0x00` array *after* the permutation. Because `permute()` is an involution ($P(P(x)) = x$), we can pass our target `0xdf` states backward through the permutation to find our required input difference (`TargetDiff`).

Instead of brute-forcing the entire 64-bit state, we only target the **first 4 bytes** of the state. We iterate through $2^{32}$ possible 4-byte inputs, hash them through Round 1, slice off the last 4 bytes, and check if their difference matches the first 4 bytes of our `TargetDiff`. This reduces the search space drastically and finds a match in milliseconds.

### Phase 2: State Patching (Block 2)
Once we find two first-blocks (`Prefix A` and `Prefix B`) that collide on the first 4 bytes of our `TargetDiff`, their back 4 bytes will be scrambled. 

However, because the protocol lets us inject a **second** 4-byte block directly into the back half of the state, we have full control over those bytes. We simply set Block 2 of Message A to `00000000`, and mathematically calculate Block 2 of Message B to force the remaining difference:

$$Block2_B = StateA_{last4} \oplus StateB_{last4} \oplus TargetDiff_{last4}$$

## 5. The Exploit Script
Here is the final script that executes the truncated dictionary attack, patches the state, and successfully generates the colliding payloads.

```python
import itertools
import json
from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
#context.log_level = 'debug'
io=remote("socket.cryptohack.org", 13395)
def send_json(data):
    io.sendline(json.dumps(data).encode())
def recv_json():
    return json.loads(io.recvline().decode())
SBOX = [
    0xf0, 0xf3, 0xf1, 0x69, 0x45, 0xff, 0x2b, 0x4f, 0x63, 0xe1, 0xf3, 0x71, 0x44, 0x1b, 0x35, 0xc8,
    0xbe, 0xc0, 0x1a, 0x89, 0xec, 0x3e, 0x1d, 0x3a, 0xe3, 0xbe, 0xd3, 0xcf, 0x20, 0x4e, 0x56, 0x22,
    0xe4, 0x43, 0x9a, 0x6f, 0x43, 0xa9, 0x87, 0x37, 0xec, 0x2, 0x3b, 0x8a, 0x7a, 0x13, 0x7e, 0x79,
    0xcc, 0x92, 0xd7, 0xd1, 0xff, 0x5e, 0xe2, 0xb1, 0xc9, 0xd3, 0xda, 0x40, 0xfb, 0x80, 0xe6, 0x30,
    0x79, 0x1a, 0x28, 0x13, 0x1f, 0x2c, 0x73, 0xb9, 0x71, 0x9e, 0xa6, 0xd5, 0x30, 0x84, 0x9d, 0xa1,
    0x9b, 0x6d, 0xf9, 0x8a, 0x3d, 0xe9, 0x47, 0x15, 0x50, 0xb, 0xe2, 0x3d, 0x3f, 0x1, 0x59, 0x9b,
    0x85, 0xe4, 0xe5, 0x90, 0xe2, 0x2d, 0x80, 0x5e, 0x6b, 0x77, 0xa1, 0x10, 0x99, 0x72, 0x7f, 0x86,
    0x1f, 0x25, 0xa3, 0xea, 0x57, 0x5f, 0xc4, 0xc6, 0x7d, 0x7, 0x15, 0x90, 0xcb, 0x8c, 0xec, 0x11,
    0x9b, 0x59, 0x1, 0x3f, 0x3d, 0xe2, 0xb, 0x50, 0x15, 0x47, 0xe9, 0x3d, 0x8a, 0xf9, 0x6d, 0x9b,
    0xa1, 0x9d, 0x84, 0x30, 0xd5, 0xa6, 0x9e, 0x71, 0xb9, 0x73, 0x2c, 0x1f, 0x13, 0x28, 0x1a, 0x79,
    0x11, 0xec, 0x8c, 0xcb, 0x90, 0x15, 0x7, 0x7d, 0xc6, 0xc4, 0x5f, 0x57, 0xea, 0xa3, 0x25, 0x1f,
    0x86, 0x7f, 0x72, 0x99, 0x10, 0xa1, 0x77, 0x6b, 0x5e, 0x80, 0x2d, 0xe2, 0x90, 0xe5, 0xe4, 0x85,
    0x22, 0x56, 0x4e, 0x20, 0xcf, 0xd3, 0xbe, 0xe3, 0x3a, 0x1d, 0x3e, 0xec, 0x89, 0x1a, 0xc0, 0xbe,
    0xc8, 0x35, 0x1b, 0x44, 0x71, 0xf3, 0xe1, 0x63, 0x4f, 0x2b, 0xff, 0x45, 0x69, 0xf1, 0xf3, 0xf0,
    0x30, 0xe6, 0x80, 0xfb, 0x40, 0xda, 0xd3, 0xc9, 0xb1, 0xe2, 0x5e, 0xff, 0xd1, 0xd7, 0x92, 0xcc,
    0x79, 0x7e, 0x13, 0x7a, 0x8a, 0x3b, 0x2, 0xec, 0x37, 0x87, 0xa9, 0x43, 0x6f, 0x9a, 0x43, 0xe4,
]
#SBOX[x]=SBOX[x ^ 0xdf]


# permute has the following properties:
# permute(permute(x)) = x
# permute(a) ^ permute(b) = permute(a ^ b)
def permute(block):
    result = [0 for _ in range(8)]
    for i in range(8):
        x = block[i]
        for j in range(8):
            result[j] |= (x & 1) << i
            x >>= 1
    return result


def substitute(block):
    return [SBOX[x] for x in block]


def hash(data):
    if len(data) % 4 != 0:
        return None

    state = [16, 32, 48, 80, 80, 96, 112, 128]
    for i in range(0, len(data), 4):
        block = data[i:i+4]
        state[4] ^= block[0]
        state[5] ^= block[1]
        state[6] ^= block[2]
        state[7] ^= block[3]
        state = permute(state)
        state = substitute(state)

    for _ in range(16):
        state = permute(state)
        state = substitute(state)

    output = []
    for _ in range(2):
        output += state[4:]
        state = permute(state)
        state = substitute(state)

    return bytes(output)
#this removes the last 16 rounds of the hash function, so that we can find a collision in the first rounds
def halfhash(data):
    if len(data) % 4 != 0:
            return None
    
    state = [16, 32, 48, 80, 80, 96, 112, 128]
    for i in range(0, len(data), 4):
        block = data[i:i+4]
        state[4] ^= block[0]
        state[5] ^= block[1]
        state[6] ^= block[2]
        state[7] ^= block[3]
        state = permute(state)
        state = substitute(state)
    return bytes(state)

#calculate all possible differences before SBOX
#let a and b be the 2 different states before SBOX, diff=a^b
#we want a^b be some array of only 0x00 and 0xdf, so that after SBOX, we can get the same output
#this recur calculates all possible differences of length 8, where each byte is either 0x00 or 0xdf 
possible_diff=[]
mapping = {}
def recur(data, depth):
    if depth == 0:
        possible_diff.append(permute(data))
        return
    recur(data+b"\x00", depth - 1)
    recur(data+b"\xdf", depth - 1)
recur(b"", 8)

#found a pair of first block to make the diff lies in the possible_diff in the second round.
found=False
for i in range(256**4):
    data = long_to_bytes(i, 4)
    hash_data = halfhash(data)
    
    front_half = hash_data[:4]
    
    for j in possible_diff:
        target_front = bytes(a ^ b for a, b in zip(front_half, j[:4]))
        
        if target_front in mapping:
            print(f"\n[+] COLLISION FRONT-HALF FOUND at iteration {i}!")
            block1_a = data
            block1_b = mapping[target_front]
            target_diff = j
            print(f"Prefix A: {block1_a.hex()}")
            print(f"Prefix B: {block1_b.hex()}")
            print(f"Target Diff Used: {j}")
            found = True
            break
    if found:
        break
            
    mapping[front_half] = data

state_a = halfhash(block1_a)
state_b = halfhash(block1_b)


block2_a = b'\x00\x00\x00\x00'


block2_b = bytes(a ^ b ^ c for a, b, c in zip(state_a[4:8], state_b[4:8], target_diff[4:8]))

payload_a = block1_a + block2_a
payload_b = block1_b + block2_b


final_hash_a = hash(payload_a)
final_hash_b = hash(payload_b)

assert final_hash_a == final_hash_b, "[-] Hashes do not match!"
print(io.recvline())
to_send={"a": payload_a.hex(), "b": payload_b.hex()}
send_json(to_send)
kk=recv_json()
print(kk)
```
