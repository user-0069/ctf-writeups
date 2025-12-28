# Static Client
## Description
>You've just finished eavesdropping on a conversation between Alice and Bob. Now you have a chance to talk to Bob. What are you going to say?\
>Connect at socket.cryptohack.org 13373
## My solution
After running `nc socket.cryptohack.org 13373`, I found out that this is Diffie-Hellman key exchange and my role was to be the "man in the middle". We cannot make any interception before Alice's message, 
so I tried to change parameters to get Bob's message first: set `A` = `g` = `0x02`. The shared key became $A^b = g^b = B$, therefore, the `B` Bob sent me was exactly the shared key.
Let's decrypt Bob's encrypted message:
```
import json
import requests
from pwnlib.tubes.remote import remote
r=remote("socket.cryptohack.org",13373)
def json_recv():
    line = r.recvline()
    line = line.decode()
    line="{" + line.split("{")[1]
    return json.loads(line)
def send_json(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

data1=json_recv() #from Alice (p,g,A)
data2=json_recv() #from Bob (B)
data3=json_recv() #from Alice (iv,enc)
to_send={'p': data1['p'],'g': data1['g'],'A': data1['g']}
send_json(to_send) # send to Bob (p,g,A)
data4=json_recv()# from Bob (B)
data5=json_recv()# from Bob (iv,enc)

shared_secret = int(data4['B'],16)
iv = data5['iv']
ciphertext = data5['encrypted']

print(decrypt_flag(shared_secret, iv, ciphertext))
```
```
Hey, what's up. I got bored generating random numbers did you see?
```
Bob got bored generating random numbers, which means he (probably) kept using the same `b`. I sent `g` = `A` this time, making $B = A^b$. As a result, the `B` Bob sent me was the shared key that Alice used to encrypt her message.
```
import json
import requests
from pwnlib.tubes.remote import remote
r=remote("socket.cryptohack.org",13373)
def json_recv():
    line = r.recvline()
    line = line.decode()
    line="{" + line.split("{")[1]
    return json.loads(line)
def send_json(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

data1=json_recv() #from Alice (p,g,A)
data2=json_recv() #from Bob (B)
data3=json_recv() #from Alice (iv,enc)
to_send={'p': data1['p'],'g': data1['A'],'A': data1['g']} 
#If A=data1['A'], the json we send will exceed 1024 bytes
send_json(to_send) # send to Bob (p,g,A)
data4=json_recv()# from Bob (B)
data5=json_recv()# from Bob (iv,enc)

shared_secret = int(data4['B'],16)
iv = data3['iv']
ciphertext = data3['encrypted']

print(decrypt_flag(shared_secret, iv, ciphertext))
```
And I got the flag:
```
crypto{n07_3ph3m3r4l_3n0u6h}
```
