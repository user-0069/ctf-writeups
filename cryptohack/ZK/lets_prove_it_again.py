import json
from pwn import *
from Crypto.Util.number import isPrime, long_to_bytes, bytes_to_long
from sage.all import gcd
#context.log_level = 'debug'
#compare to the easy version in "lets prove it", this chall reuse v
#lets say we have r1=v-c1.flag mod(p1-1) and r2=v-c2.flag mod(p2-1)
#c,v,flag is small enough so only wrap around p1 and p2 once
#r1-(p1-1)=v-c1.flag , r2-(p2-1)=v-c2.flag
#subtract the two equation, we have (r1-r2)-((p1-1)-(p2-1))= (c2-c1).flag (1)
#one more flaw is that c is hash(t^y^g^rand(2,1024)), so we can bruteforce possible c1,c2
#we send seeds to control the rand, predict p1,p2, and by knowing r1,r2 and bruteforcing c1,c2, we can get the flag from (1)
io=remote("socket.cryptohack.org", 13431)
def send_json(data):
    io.sendline(json.dumps(data).encode())
def recv_json():
    return json.loads(io.recvline().decode())
def xor(a, b):
     assert len(a) == len(b)
     return bytes(x ^ y for x, y in zip(a, b))

def xor_nonce(byte_str, nonce):
    start = byte_str[:7]
    end = byte_str[-1:]
    middle = byte_str[7:-1]
    return start + xor(middle, nonce) + bytes(end)

io.recvuntil(b"instance: ")
init_nonce = bytes.fromhex(io.recvline().strip().decode())
print(init_nonce)
to_send = {"option": "get_proof"}
send_json(to_send)
data = recv_json()
print(data)
to_send = {"option": "refresh", "seed":"00"}
send_json(to_send)
data = recv_json()
print(data)
nonce=init_nonce+b"\00"
rand=random.Random(nonce)
def getPrime(N):
        while True:
            number = rand.getrandbits(N) | 1
            if isPrime(number, randfunc=lambda x: long_to_bytes(rand.getrandbits(x))):
                break
        return number
g=2
to_send = {"option": "get_proof"}
send_json(to_send)
kk = recv_json()
r1=kk['r']
t1=kk['t']
y1=kk['y']
p1=getPrime(1024)
to_send={"option": "get_proof"}
send_json(to_send)
kk = recv_json()
print(kk)
to_send={"option": "refresh", "seed": "01"}
send_json(to_send)
kk = recv_json()
print(kk)
nonce=init_nonce+b"\01"
rand=random.Random(nonce)
p2=getPrime(1024)
to_send={"option": "get_proof"}
send_json(to_send)
kk = recv_json()
r2=kk['r']
t2=kk['t']
y2=kk['y']
c1=bytes_to_long(hashlib.sha3_256(long_to_bytes(t1^g^y1)).digest())
c2=bytes_to_long(hashlib.sha3_256(long_to_bytes(t2^g^y2)).digest())
for i in range(2,1024):
    for j in range(2,1024):
        c1=bytes_to_long(hashlib.sha3_256(long_to_bytes(t1^g^y1^i)).digest())
        c2=bytes_to_long(hashlib.sha3_256(long_to_bytes(t2^g^y2^j)).digest())
        cand=abs(((r1-p1)-(r2-p2))//(c2-c1))
        if(b"crypto" in long_to_bytes(cand)):
            xored_flag=long_to_bytes(cand)
            break
flag=xor_nonce(xored_flag, init_nonce)
print(xored_flag)
print(flag)


