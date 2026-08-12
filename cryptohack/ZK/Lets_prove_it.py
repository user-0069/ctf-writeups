import itertools
import json
from pwn import *
from Crypto.Util.number import isPrime, long_to_bytes, bytes_to_long
#context.log_level = 'debug'
#the author use random.Random(seed) and let us choose the seed, so we can reproduce all the random steps
#the core equation of this problem is r=v-c*flag mod(p-1)
#note that v and c are only 512 bit long, FLAG is 39 bytes long and all of them are much small compare to 1024 bit p
#we modify the equation to get p-1-r=c*flag +v (because p-1 is so large, we can ignore the mod p-1)
#divide both sides by c, we can get flag=(p-1-r)/c + v/c, where v/c is tiny, so we can ignore it and get the flag
#just calculate (p-1-r)/c and xor it with the nonce to get the flag
#base on the flag, there is also another solution using lattice:
# [p-1  0   0]
# [c    W1   0]
# [r    0   W2]
#the target vector is [v,flag*W1,W2]
io=remote("socket.cryptohack.org", 13430)
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
p=getPrime(1024)
to_send = {"option": "get_proof"}
send_json(to_send)
kk = recv_json()
r=kk['r']
c = bytes_to_long(hashlib.sha3_256(long_to_bytes(kk['t'] ^ kk['y'] ^ 2)).digest()) ** 2
flag = long_to_bytes((p-1-r)//c,39)
flag = xor_nonce(flag, init_nonce)
print(flag)


