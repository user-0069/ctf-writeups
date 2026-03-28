## Description
[challenge](https://dreamhack.io/wargame/challenges/386)
## Solution
The `token` has the length of 160 bytes, so the last block of `token`+ `b"test"` must be `b"test"`+`padding`. We want to fake a ciphertext to make this last block be `b"show"`+`padding`.\
In CBC mode, $C_i = E(P_i \bigoplus C_{i-1})$. So if we want to fake the last block ($C_{11}$), we need to find $E(pad(b"show") \bigoplus C_{10})$. That is possible as $C_{10}$ can be
taken from the initial ciphertext. 
```
from pwn import *
from sage.all import *
from Crypto.Util.number import long_to_bytes
import base64
from Crypto.Util.Padding import pad
context.log_level = 'debug'
io=remote("host8.dreamhack.games", 21625)
ct=(io.recvline().strip()).split(b": ")[-1]
ct=base64.b64decode(ct)
io.recvline()
io.sendlineafter(b": ", base64.b64encode(ct[-32:-16]))
io.sendlineafter(b": ", base64.b64encode(pad(b"show",16)))
ct_show=io.recvline().strip().split(b":")[-1]
ct_show=base64.b64decode(ct_show)[16:32]
io.sendlineafter(b": ", base64.b64encode(ct[:-16]+ct_show))
io.recvline()
io.recvline()
```

```
DH{8a380d0456c0e6c160403c48f6a7fbbb7a37e09b}
```
