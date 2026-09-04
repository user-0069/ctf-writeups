

## Overview
In this challenge, we participate in a Shamir's Secret Sharing Scheme (SSSS) key ceremony to reconstruct a Bitcoin private key. The threshold is 5 out of 6 shares, operating over the 13th Mersenne prime ($p = 2^{521} - 1$). Our goal is to execute an "evil plan":
1. Sabotage the first combination round.
2. Inject a fake private key in the second round.
3. Recover the real private key and steal the funds.

The catch: our teammates' shares are censored in the chat (`0x???`), preventing standard polynomial interpolation.

## Vulnerability 

### Part 1: Recovering the Real Secret
Since we cannot see the other 4 shares, we cannot interpolate the secret directly. However, the server combines the shares using Lagrange interpolation at $x = 0$:

$$S = c_2y_2 + c_3y_3 + c_4y_4 + c_5y_5 + c_6y_6 \pmod p$$

By submitting $y_6 = 0$ in the first round, we force the server to evaluate the polynomial without our share's contribution. The server then broadcasts this "fake" private key ($S_{\text{fake}}$) to the chat:

$$S_{\text{fake}} = c_2y_2 + c_3y_3 + c_4y_4 + c_5y_5 + c_6(0) \pmod p$$

The relationship between the real secret and the broadcasted fake secret is simply:

$$S_{\text{real}} = S_{\text{fake}} + c_6y_6 \pmod p$$

We can calculate our specific Lagrange basis polynomial coefficient ($c_6$) using the known $x$-coordinates ($2, 3, 4, 5, 6$):

$$c_6 = \prod_{j \in \{2,3,4,5\}} \frac{0 - x_j}{x_6 - x_j} = \frac{-2}{4} \cdot \frac{-3}{3} \cdot \frac{-4}{2} \cdot \frac{-5}{1} = 5$$

Therefore, $S_{\text{real}} = S_{\text{fake}} + 5y_6 \pmod p$.

### Part 2: Forging the Fake Key
For the second round, we must force the combined secret to equal a specific fake private key. We can exploit the modular arithmetic by submitting an $x$-coordinate equal to the prime modulus ($x = 2^{521} - 1 \equiv 0 \pmod p$). 

When $x = 0$, our share directly dictates the $y$-intercept of the polynomial. By sending `{"x": 2**521 - 1, "y": fake_privkey}`, we trivially overwrite the combined secret.

## Exploit Script

```python
import json
from pwn import *
from Crypto.Util.number import isPrime, long_to_bytes, bytes_to_long
from sage.all import *
context.log_level = 'debug'
def send_json(data):
    io.sendline(json.dumps(data).encode())
def recv_json():
    return json.loads(io.recvline().decode())
io=remote("socket.cryptohack.org", 13384)
kk=recv_json()
my_y=int(kk['y'], 16) #collect my real y
while("msg" not in kk or "hyper" not in kk['msg']):
    kk=recv_json()
send_json({"x":6,"y":"00"}) #send fake y
kk=recv_json()
fake_pk=int(kk['privkey'], 16) #fake private key from our fake y
while("msg" not in kk or "hyper" not in kk['msg']):
    kk=recv_json()

prime=2**521-1 # 13th Mersenne prime
fake_acc="8b09cfc4696b91a1cc43372ac66ca36556a41499b495f28cc7ab193e32eadd30" #fake address
send_json({"x":prime,"y":fake_acc})
io.recvline()
io.recvline()
io.recvline()
real_pk=(fake_pk+5*my_y)%prime #calculate real prvkey using Lagrange interpolation formula at x=0

send_json({"privkey":hex(real_pk)})
print(io.recvall())




```
