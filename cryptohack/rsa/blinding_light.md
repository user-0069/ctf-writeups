# Blinding Light
## Description
[RSA challenges](https://cryptohack.org/challenges/rsa/)
## My solution
Denote `ADMIN_TOKEN` as $m$, we need to find $m^d {mod} (N)$ without signing $m$ directly. However we can get the signature 
of $(m.k)$ and $k$. Knowing $(m.k)^d {mod}(N)$ and $k^d{mod}(N)$, we can easily obtain $m^d$.
```
to_send={"option":"get_pubkey"}
send(to_send)
data=recv()

n=data["N"]
n=int(n,16)
e=data["e"]
msg=bytes_to_long(admin_token)
msg=msg*randd % n
to_send={"option":"sign","msg":long_to_bytes(msg).hex()}
send(to_send)
data=recv()
sig=data["signature"]
sig=int(sig,16)
to_send={"option":"sign","msg":long_to_bytes(randd).hex()}
send(to_send)
data=recv()
rand_sig=data["signature"]
rand_sig=int(rand_sig,16)
sig=(sig*inverse(rand_sig,n))%n
to_send={"option":"verify","msg":admin_token.hex(),"signature":hex(sig)}
send(to_send)
data=recv()

print(data)
```
```
{'response': 'crypto{m4ll34b1l17y_c4n_b3_d4n63r0u5}'}
```
