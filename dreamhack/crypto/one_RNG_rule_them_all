from pwn import *
from Crypto.Util.number import *

leaks = [0] * 5
leaks[0] = 0xa1e095c2dee3c17f
leaks[1] = 0x1b07e2a7755985a2
leaks[2] = 0x4c842c66e0b95cc9
leaks[3] = 0x1c7e09d41a0187a4
leaks[4] = 0x9faa2daaee6ab523
e = 65537
n = 0x5bcd1c00a8f744ecef35e0859bc5c0ce21a8bb6bbd00ffa9b819c5109686f1b35e24ddc227729bbb8e88e3521dcb78d40af98c1b07929474432a46c0ea0130811c7307229f5a7ee21669da8c4f0ed83c725bb462b3bddfd3087632da39e8847503de08fdfc935fe544730e35419c93675b68ac565d488c3e0a172f0aacea0c61
c = 0x42decad46a8c5e27696370425c612dad5db72fe683c6f0548c765901c0fcfd389fc98d0cbcadef721d53d83ca730bac25166fccd1536af820cdb6263a7a1fa4720e5daebe9060eea26d6a4c6541ca74ed682327f9ea087bde51bcf090108a7ce110641896e469bf88f547e7883fc51f9f5d261ad3843ce6b51e6741ba38a8533
m = 1<<64

### Build LCG part

#find a,b
a=(leaks[2]-leaks[1])%m*pow((leaks[1]-leaks[0])%m,-1,m)%m
b=(leaks[1]-a*leaks[0])%m
class LCG:
    def __init__(self, a, b, m,seed):
        self.a = a
        self.b = b
        self.m = m
        self.state = seed
    def next(self):
        b=self.state
        self.state = (self.a * self.state + self.b) % self.m
        
        return b
    def rand(self,bits):
        res = 0
        for _ in range(bits // 64):
            res = (res<<64) | self.next()
        return res
    def rollback(self):
        ainv = pow(self.a, -1, self.m)
        self.state = ((self.state - self.b) * ainv) % self.m
RNG=LCG(a,b,m,leaks[0]) #LCG that generates p,q and mask

### Gen public key part
# n is 1024-bit so p and q are 512-bit primes

# This part is equivalent to p=getPrime(512) 
while(p==0 or n%(1|p|(1<<511))!=0):
    p=(p<<64)| RNG.next()
    p=p%(1<<512)
p=1|p|(1<<511) # ensure p is an odd 512-bit prime

# This part is equivalent to q=getPrime(512)
q=0
while(q==0 or n%(1|q|(1<<511))!=0):
    q=(q<<64)| RNG.next()
    q=q%(1<<512)
q=1|q|(1<<511) # ensure q is an odd 512-bit prime

### Find the mask 

mask=RNG.rand(1024)
phi=(p-1)*(q-1)
d=inverse(e,phi)
m=pow(c,d,n)
print(xor(long_to_bytes(m),long_to_bytes(mask))) 
# xor with int doesnt work, so i xor byte by byte (big endian and little endian issue) 
# DH{hybrid_lcg_rsa_stream_crypt0_challenge_lvl9_10}...   
