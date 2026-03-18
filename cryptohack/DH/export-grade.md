# Export-grade

## Description

> Alice and Bob are using legacy codebases and need to negotiate parameters they both support. You've man-in-the-middled this negotiation step, and can passively observe thereafter. How are you going to ruin their day this time?\
Connect at `socket.cryptohack.org 13379`

## My Solution
I send to Bob the only option `DH64` to make the Diffie-Hellman key size as small as possible. 
```
~$ nc socket.cryptohack.org 13379 
Intercepted from Alice: {"supported": ["DH1536", "DH1024", "DH512", "DH256", "DH128", "DH64"]}
Send to Bob: {"supported": ["DH64"]}
Intercepted from Bob: {"chosen": "DH64"}
Send to Alice: {"chosen": "DH64"}
Intercepted from Alice: {"p": "0xde26ab651b92a129", "g": "0x2", "A": "0x77cabb6add786395"}
Intercepted from Bob: {"B": "0x8a56a1f5c674a937"}
Intercepted from Alice: {"iv": "a8a4e385fb2ef4c963975c89e4a56fa6", "encrypted_flag": "99cdcdee6ea322586bd7a8c6423ad55919db98f6c5b960854267f8be7df8c8c4"}
```
The key size is small enough to use `discrete_log` (which has time complexity of O($$\sqrt{p}$$ $log  p$)) and find `b`.
```
from sympy.ntheory import discrete_log
g= int("0x2",16)
A= int("0x77cabb6add786395",16)
B= int("0x8a56a1f5c674a937",16)
p= int("0xde26ab651b92a129",16)
b= discrete_log(p,B,g)
print(b)
```
```
6093130202163721708
```
I proceed to calculate `shared_secret` and decrypt `encrypted_flag` to get the flag.
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
iv= "a8a4e385fb2ef4c963975c89e4a56fa6"
encrypted_flag= "99cdcdee6ea322586bd7a8c6423ad55919db98f6c5b960854267f8be7df8c8c4"

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


shared_secret = pow(A,b,p)
ciphertext = encrypted_flag

print(decrypt_flag(shared_secret, iv, ciphertext))
```
```
crypto{d0wn6r4d35_4r3_d4n63r0u5}
```


