

## Challenge Overview
This challenge simulates a Zero-Knowledge proof system loosely based on Zcash's Sapling protocol. The server generates 64 bytes of random data, splits it into 8 chunks, and constructs a 3-layer Merkle tree. 

To get the flag, we must successfully query the `do_proof` endpoint with the correct Merkle Root hash. However, we start with only 99 credits, and purchasing the required 8 leaf nodes (Layer 0) costs 160 credits.

## Vulnerabilities Exploited

### 1. Race Condition (Logic Flaw)
When requesting nodes via the `get_nodes` option, the server attempts to verify if we have enough credits using a background thread:
```python
t = Thread(target=self.request_checker, args=[wanted_nodes])
t.start()
```
Because there is no `t.join()`, the main thread does not wait for the calculation to finish. It immediately checks `if self.balance_validated != False`. By requesting a massive number of nodes (e.g., `10000000`), we force the background thread into a loop that takes hundreds of milliseconds to finish calculating the cost. The main thread wins the race, evaluates `None != False` as `True`, and grants us the data.

### 2. Forgiving Python List Slicing
By requesting `10000000` nodes, the server executes `self.nodes[0][:10000000]`. In Python, slicing an array out-of-bounds does not throw an error; it simply returns the entire available array, cleanly giving us all 8 leaf nodes for free.

### 3. Replay Attack (Missing Nullifier)
The `saplin_proof` function only checks if the submitted hash equals the root hash. In a real-world scenario, this lacks a "nullifier" or nonce to mark the proof as spent. This means an attacker could theoretically eavesdrop on a valid transaction and infinitely replay the same proof to drain funds.

---

## Exploit Script


```python
from hashlib import sha256
from Crypto.Util.number import long_to_bytes
from pwn import *
import json
import ast
io=remote("socket.cryptohack.org", 13414)
def send_json(data):
    io.sendline(json.dumps(data).encode())
def recv_json():
    return json.loads(io.recvline().decode())
def merge_node(a,b):
    return sha256(a+b).digest()
io.recvuntil(b"implementation!\n")
to_send ={"option":"get_nodes","nodes":"1,100000"}
send_json(to_send)
kk=recv_json()
arr=ast.literal_eval(kk["msg"])
a,b,c,d=arr[0]
a=bytes.fromhex(a)
b=bytes.fromhex(b)
c=bytes.fromhex(c)
d=bytes.fromhex(d)
left=merge_node(a,b)
right=merge_node(c,d)
root=merge_node(left,right)
to_send ={"option":"do_proof","root":root.hex()}
send_json(to_send)
kk=recv_json()
print(kk)
```
