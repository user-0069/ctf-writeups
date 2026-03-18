# Static Client 2
## Description
>Bob got a bit more careful with the way he verifies parameters. He's still insisting on using the p and g values provided by his partner. Wonder if he missed anything?
>Connect at socket.cryptohack.org 13378
## My solution
If you send exactly Alice's parameters to Bob, you will realized that Bob still reuse `b` .
I tried setting `g` = `A` and `A` = `g` but it was carefully verified by Bob:
```
Bob says to you: {"error": "Those parameters look dodgy, aborting"}
```
```
Bob says to you: {"error": "That g value looks mighty suspicious"}
```
However, I then modified `A` a little bit: `A` = `0x04`, and Bob accepted that parameter. The shared key became $4^b = B^2$, and I decrypted Bob's encrypted message:
```
My new Diffie-Hellman code is perfect. I implemented all poncho's suggestions!
```
I searched for "poncho's suggestions" (I had no idea what it was!), and maybe he was referring to this comment from an user named *poncho*:\
https://crypto.stackexchange.com/questions/25027/verifying-diffie-hellman-parameters-someone-else-generated/25030#25030

He talked about weak DH group and mentioned choosing `p`. The case that `p-1` is a composite with many small prime factors, was about Pohlig-Hellman attack: find x that $g^x \equiv h {mod} p $, with $p-1$ is a 
[smooth number](https://en.wikipedia.org/wiki/Smooth_number).

Pohlig-Hellman attack works very well when `p-1` is a smooth number. This is because the algorithm can divide the problem into smaller Discrete Logarithm subproblems and use Chinese Remainder Theorem (CRT) to combine
the results of those subproblems:\
![](https://upload.wikimedia.org/wikipedia/commons/thumb/6/66/Pohlig-Hellman-Diagram.svg/500px-Pohlig-Hellman-Diagram.svg.png)

```
data1=json_recv() #from Alice (p,g,A)
data2=json_recv() #from Bob (B)
data3=json_recv() #from Alice (iv,enc)
i = 2
p2 = 1
p=int(data1['p'],16)
while p2 < p or not is_prime(p2 + 1):
    p2 *= i
    i += 1
p2+=1
# generate a prime p2 that p2-1 is smooth (p2= x! + 1 in this case)
to_send={'p': hex(p2),'g': '0x02','A': data1['A']} 
send_json(to_send) # send to Bob (p,g,A)
data4=json_recv()# from Bob (B)
data5=json_recv()# from Bob (iv,enc)

b=discrete_log(p2,int(data4['B'],16),2) #find b that 2^b = B (mod p2)
# discrete_log includes Pohlig-Hellman algorithm to solve DLP
shared_secret = pow(int(data1['A'],16),b,int(data1['p'],16)) # shared key = A^b (mod p)
iv = data3['iv']
ciphertext = data3['encrypted']

print(decrypt_flag(shared_secret, iv, ciphertext))
```

It took about a minute to get the flag: `crypto{uns4f3_pr1m3_sm4ll_oRd3r}`
