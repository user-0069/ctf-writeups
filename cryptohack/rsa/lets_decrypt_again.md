# Let's Decrypt Again
## Description
[RSA challenges](https://cryptohack.org/challenges/rsa/)
## My solution
To get the flag we need to get all 3 shares of it. Lets denote $m1, m2, m3$ are the messages that pass the check (`re.match()` and `endswith(self.suffix)`), $m$ as the
value of the original ones (the third message also need to pass the `btc_check()`, which I found confusing at first, but it turns out
that I just need to provide a *valid bitcoin address*).\
The problem become solving **DLP**: finding $e_i$ such that $m^{e_i} \equiv m_i \quad mod(N)$ for each $i$, in which $N$ is a prechosen 
composite modulus. We need to find N with smooth order to run **DLP** smoothly. I choose $p^k$ with the order being $p^{k-1}.(p-1)$ and p is small enough so that the order
is factorable.
```
btc_addr = b"1BoatSLRHtKNngkdXEeobR76b53LETtpyT"

target = b'We are hyperreality and Jack and we own CryptoHack.org'
msg = [
    b"This is a test(.*)for a fake signature.",
    b"My name is Jack and I own CryptoHack.org",
    b"Please send all my money to " + btc_addr
]

r.recvline()
to_send = {"option": "get_signature"}
send(to_send)
kk = recv()
signature = int(kk['signature'], 16)
ee=int(kk['E'],16)
nn=int(kk['N'],16)  

def generate_weak_prime():
    x=getPrime(10)
    return x

p = generate_weak_prime()
N = p**80 

to_send = {
    "option": "set_pubkey",
    "pubkey": hex(N)
}
send(to_send)
kk = recv()
suffix = kk['suffix']
R = Zmod(N)
share = [0, 0, 0]
for i in range(len(msg)):
    print(f"[*] Solving Stage {i}...")
    
    full_msg_bytes = msg[i] + suffix.encode()
    print(full_msg_bytes)
    em = emsa_pkcs1_v15_encode(full_msg_bytes)
    em_int = bytes_to_long(em)
    
    e = R(em_int).log(R(signature))
    to_send = {
        "option": "claim", 
        "msg": full_msg_bytes.decode(),
        "e": hex(e),
        "index": i
    }
    send(to_send)
    kk = recv()
    share[i] = int(kk['secret'],16)
xored_share = share[0] ^ share[1] ^ share[2]
print(bytes.fromhex(hex(xored_share)[2:]))
```
As my choice for $N$ is not optimal and ideal enough, it takes several runs to finally get the flag
```
b"crypto{let's_decrypt_w4s_t0o_ez_do_1t_ag41n}"
```
