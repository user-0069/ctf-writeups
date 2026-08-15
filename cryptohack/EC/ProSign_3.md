
## Challenge Overview


In this challenge, we are presented with a service that provides two endpoints:
1. `sign_time`: Generates an ECDSA signature for a formatted time message (`Current time is {m}:{n}`).
2. `verify`: Verifies an arbitrary signature `(r, s)` against a provided message `msg`. If `msg == "unlock"` and the signature is valid, it returns the flag.

---

## Vulnerability Analysis

In standard ECDSA, the security of the signature heavily depends on generating a cryptographically secure, random nonce $k \in [1, n-1]$ for every signature, where $n$ is the prime order of the curve subgroup.

Looking closely at the server source code for `sign_time()`:

```python
def sign_time(self):
    now = datetime.now()
    m, n = int(now.strftime("%m")), int(now.strftime("%S"))
    current = f"{m}:{n}"
    msg = f"Current time is {current}"
    hsh = self.sha1(msg.encode())
    sig = self.privkey.sign(bytes_to_long(hsh), randrange(1, n))
    return {"msg": msg, "r": hex(sig.r), "s": hex(sig.s)}
```

### The Bug: Variable Shadowing
* At the module level, `n` was initialized to the curve's subgroup order: `n = g.order()`.
* Inside `sign_time()`, the variable `n` is overwritten (shadowed) by the current second: `int(now.strftime("%S"))`.
* As a result, `randrange(1, n)` samples $k$ uniformly from the tiny range $[1, 59]$ instead of $[1, \approx 2^{192}]$.

---

## Exploitation Strategy

### 1. Recovering the Nonce $k$
In ECDSA, the signature component $r$ is computed from the point $R = k \cdot G$:
$$r = R_x \pmod n$$

Because $k \in [1, 59]$, we can simply brute-force all possible values of $k \in [1, 59]$, compute $k \cdot G$, and check if the resulting $x$-coordinate matches the received signature's $r$.

### 2. Recovering the Private Key $d$
The signature equation for ECDSA is:
$$s \equiv k^{-1}(z + r \cdot d) \pmod n$$

Where:
* $z = \text{bytes-to-long}(\text{SHA-1}(msg))$
* $r, s$ are from the captured signature
* $k$ is the recovered nonce
* $n$ is the actual curve order ($\approx 2^{192}$)

Solving for the private key $d$:
$$d \equiv r^{-1}(s \cdot k - z) \pmod n$$

### 3. Forging a Signature for `"unlock"`
With the private key $d$ in hand, we compute:
1. $z({\text{unlock}}) = \text{bytes-to-long}(\text{SHA-1}(\text{"unlock"}))$
2. Choose any valid $k_{\text{forge}}$ (or reuse $k$) and compute:
   $$s' \equiv k_{\text{forge}}^{-1}(z_{\text{unlock}} + r \cdot d) \pmod n$$
3. Send `{"option": "verify", "msg": "unlock", "r": hex(r), "s": hex(s')}` to obtain the flag.

---

## Solution Script

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import *
import hashlib
from sage.all import *
from pwn import *
import json
#params of sec192 curve
p=0xfffffffffffffffffffffffffffffffeffffffffffffffff
a=0xfffffffffffffffffffffffffffffffefffffffffffffffc
b=0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
Gx=0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
Gy=0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
n=0xffffffffffffffffffffffff99def836146bc9b1b4d22831

EC=EllipticCurve(GF(p),[a,b])
G=EC(Gx,Gy)

io=remote('socket.cryptohack.org', 13381)
def send_json(data):
    io.sendline(json.dumps(data).encode())
def recv_json():
    return json.loads(io.recvline().decode())
def sha1(msg):
    return hashlib.sha1(msg).digest()
print(io.recvline())
to_send={'option':"sign_time"}
send_json(to_send)
kk=recv_json()
print(kk)
msg=kk['msg']
r=int(kk['r'],16)
s=int(kk['s'],16)
hsh=sha1(msg.encode())
h=bytes_to_long(hsh)
for i in range(1,60):
    k=i
    r1=(k*G).xy()[0]
    r1=int(r1)%n
    if(r1==r):
        d=(inverse_mod(r,n)*(s*k-h))%n
        new_h=bytes_to_long(sha1(b'unlock'))
        new_s=(inverse_mod(k,n)*(new_h+d*r))%n
        to_send={'option':"verify",'msg':"unlock",'r':hex(r),'s':hex(new_s)}
        send_json(to_send)
        kk=recv_json()
        print(kk)
        break




```

---

## Lessons
* **Nonce Integrity:** Nonce reuse or small/predictable nonces completely break ECDSA and allow instantaneous private key extraction.
* **Deterministic ECDSA (RFC 6979):** Generates $k$ deterministically via HMAC of the private key and message hash, eliminating RNG failure and variable scoping risks.
* **Variable Scoping:** Be cautious of name shadowing in Python (`n` reassigned inside the function scope).
