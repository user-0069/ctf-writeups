# Oh SNAP
## Description
>Here's the start of my fast network authentication protocol, so far I've only implemented the "Ping" command so there shouldn't be any way to recover the key.

```
from Crypto.Cipher import ARC4


FLAG = ?


@chal.route('/oh_snap/send_cmd/<ciphertext>/<nonce>/')
def send_cmd(ciphertext, nonce):
    if not ciphertext:
        return {"error": "You must specify a ciphertext"}
    if not nonce:
        return {"error": "You must specify a nonce"}

    ciphertext = bytes.fromhex(ciphertext)
    nonce = bytes.fromhex(nonce)

    cipher = ARC4.new(nonce + FLAG.encode())
    cmd = cipher.decrypt(ciphertext)
    if cmd == b"ping":
        return {"msg": "Pong!"}
    else:
        return {"error": f"Unknown command: {cmd.hex()}"}
```
## My solution and explanation
![](https://media.geeksforgeeks.org/wp-content/cdn-uploads/55-2.png)

The picture above shows how ARC4 works(nonce in this problem is actually the IV in the process).

Looking at the `send_cmd` function, we can see that after making a request, we can easily obtain $keystream(key) = plaintext \bigoplus ciphertext$ . So the main problem here is to get the `key` 
knowing `nonce` and `keystream(nonce+key)` (we can even choose `nonce`). 

After searching for attacks on ARC4, I found out that FMS attack fit perfectly with this problem. 

This attack targets at the Key Schduling Algorithm (KSA):
```
begin ksa(with int keylength, with byte key[keylength])
    for i from 0 to 255
        S[i] := i
    endfor
    j := 0
    for i from 0 to 255
        j := (j + S[i] + key[i mod keylength]) mod 256
        swap(S[i],S[j])
    endfor
end
```

Let `key`=`nonce+key` from now to avoid confusion. 

Lets denote j after the $i^{th}$ operation in the second loop $j_{i}$. So from the line `j := (j + S[i] + key[i mod keylength]) mod 256` we can rewrite it as $key[i] = j_{i} - j_{i-1} - S[i]$ (remove mod keylength for simplicity). 
Up to the $(i-1)^{th}$ operation, we can simulate the change of `j` and `S`, so $j_{i-1}$ and $S[i]$ are known. **If we can somehow know $j_{i}$, we can obtain the value of key[i].**


FMS attack get key[v] (v>=3) by: 
* Try all `nonce` in form `(v,255,x)` (x can be any number in range [0,255]).
* The most frequent value of the first byte of `keystream(key)` across 256 trials is (likely) the value of the $v^{th}$ byte of the `key`.\
**But why?**

With right implementation, `Sbox` after the second operation will look like:

|i  | 0 | .... |
|---|---|------|

Lets *assume* `Sbox` looks like this before the $i^{th}$ round (which means Sbox[ $j_{i}$ ] has been untouched since Sbox initialization):
|Sbox |i  | 0 | ... | ?   | ... | $j_{i}$|
|-----|---|---|-----|-----|-----|--------|
|Index| 0 | 1 | ....| i   | ....| $j_{i}$|

After the round, it looks like:
|Sbox |i  | 0 | ... | $j_{i}$  | ... | ?        |
|-----|---|---|-----|----------|-----|----------|
|Index| 0 | 1 | ....| i        | ....| $j_{i  }$|

Lets again *assume* Sbox[0], Sbox[1], Sbox[i] stay unchanged till the process ends. Mathematicians proved that the assumptions we made both hold true for 5% of the time.

If the assumptions hold true then in the PRGA phase:
```
begin prga(with byte S[256])
    i := 0
    j := 0
    while GeneratingOutput:
        i := (i + 1) mod 256
        j := (j + S[i]) mod 256
        swap(S[i],S[j])
        output S[(S[i] + S[j]) mod 256]
    endwhile
end
```

KS[0] = S[S[1]+S[S[1]]] = S[0 + S[0]] = S[i] = $j_{i}$ 

So we find the way to get $j_{i}$ only by requesting `send_cmd` (of course with only roughly 5% accuracy, but thats enough for 256 trials). Try 256 times with different x in `nonce`, plug $j_i$ we found
into $key[i] = j_{i} - j_{i-1} - S[i]$, do some counting to get the most frequent value. That's key[i].

```
import requests
from Crypto.Util.Padding import unpad
from Crypto.Cipher import ARC4
from Crypto.Util.number import*
s = requests.Session()

def send_cmd(ciphertext, nonce):
    url = f"http://aes.cryptohack.org/oh_snap/send_cmd/{ciphertext.hex()}/{nonce.hex()}/"
    r = s.get(url) 
    return r.json()
key = [None]*3
for i1 in range(len(key)-3,34):
    cnt = [0] * 256
    for i2 in range(256):
        key[0] = i1+3
        key[1] = 255
        key[2] = i2
        j = 0
        box = [i for i in range(256)]
        for i in range(key[0]):
            j = (j + box[i] + key[i]) % 256
            box[i],box[j]=box[j],box[i]
        nonce = long_to_bytes(key[0])+long_to_bytes(key[1])+long_to_bytes(key[2])
        a = send_cmd(bytes.fromhex("00"),nonce)
        a=a['error']
        keyStreamByte = int((a.split(': ')[1]),16)
        keyByte = (keyStreamByte - j - box[key[0]]) % 256
        cnt[keyByte] += 1
        opt = cnt.index(max(cnt))
    key.append(opt)

for i in key[3:]:
    print(chr(i),end="")
```

It may takes minutes to get the flag.
```
crypto{w1R3d_equ1v4l3nt_pr1v4cy?!}
```





