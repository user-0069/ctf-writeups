# Signing Server
## Description
[RSA challenges](https://cryptohack.org/challenges/rsa/)
## My solution
The `get_secret` option gives us the encrypted flag, while the `sign` option allow us to send any text $T$ and return $T^d mod(n)$.
So if we request the server to sign the encrypted flag, the `sign` function will work as a decrypting function.
```
to_send={"option":"get_secret"}
send(to_send)
data1=recv()
to_send={"option":"sign","msg":data1['secret']}
send(to_send)
data2=recv()
m=int(data2['signature'],16)
flag=long_to_bytes(m)
print(flag)
```
```
b"TODO: audit signing server to make sure that meddling hacker doesn't get hold of my secret flag: crypto{d0n7_516n_ju57_4ny7h1n6}"
```


