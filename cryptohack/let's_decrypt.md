# Let's Decrypt
## Description
[RSA challenges](https://cryptohack.org/challenges/rsa/)
## My solution
The `msg` in our verification must match `r = re.match(r'^I am Mallory.*own CryptoHack.org$', msg)`, so we cannot do much without keeping
`msg` in that form. Therefore, we need to focus on which `N` and `e` should be sent. Let's denote the signature that we receive by 
`get_signature` as $A$, and the `msg` as $B$. Our goal is to make $A^e \equiv B {mod(N)}$. If $A>2B$, we have $A \equiv B {mod} (A-B)$. Choosing
$N=A-B$ and $e=1$ solves this problem.
```
m2=b'I am Mallory own CryptoHack.org'
m1=b'We are hyperreality and Jack and we own CryptoHack.org'
r.recvline()
to_send={"option":"get_signature"}
send(to_send)
data=recv()
signature=data['signature']
n=data['N']
e=data['e']
A = int(signature,16)
n=int(n,16)
e=int(e,16)
B=emsa_pkcs1_v15_encode(m2)
B=int.from_bytes(B,byteorder='big')
to_send={
    "option": "verify",
    "msg": m2.decode(),
    "e" :hex(1),
    "N" :hex(A-B),
}
send(to_send)
data=recv()
print(data)
```
```
{'msg': "Congratulations, here's a secret: crypto{dupl1c4t3_s1gn4tur3_k3y_s3l3ct10n}"}
```
