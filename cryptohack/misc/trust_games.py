import json
from pwn import *
from Crypto.Util.number import isPrime, long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from sage.all import *
context.log_level = 'debug'
m=2**48
a = 0x1337deadbeef
b = 0xb
io=remote("socket.cryptohack.org", 13396)
def recv_json():
    line = io.recvline()
    return json.loads(line.decode())
def send_json(data):
    request = json.dumps(data).encode()
    io.sendline(request)

# this chall refresh the prng seed every 16 times
# the initial plaintext, iv, key is all 16 bytes, fitting with the refresh period
# however, when server assign player name for us, it uses just 8 bytes
# therefore, any plaintext, iv and key we get from get_a_challenge come from 2 different consecutiveseeds
# as a result, iv[0:8] use the same seed with key[8:] and plaintext[8:] use the same seed with key[0:8]
# we can get the original seed from 8 leaks by applying LLL
# the matrix will look like this:
# [1, a, a^2, a^3, a^4, a^5, a^6, a^7, 0]
# [b*c_0, b*c_1, b*c_2, b*c_3, b*c_4, b*c_5, b*c_6, b*c_7, 0]
# [L[0], L[1], L[2], L[3], L[4], L[5], L[6], L[7], W]
# [m, 0, 0, 0, 0, 0, 0, 0, 0]
# [0, m, 0, 0, 0, 0, 0, 0, 0]
# ...
# [0, 0, 0, 0, 0, 0, 0, m, 0]
#where L[i] = leaks[i] * (m//256), c_i = b*(a^n-1)/(a-1)
#LLL output a vector of 8 40-bit integer, which is the hidden low bits of the states




io.recvline()
to_send ={"option": "get_a_challenge" }
send_json(to_send)
kk=recv_json()

byte_pt=bytes.fromhex(kk['plaintext'])[8:]
byte_iv=bytes.fromhex(kk['IV'])[0:8]
W=2**40

# recover from plaintext[8:]
L = []
for i in range(0,len(byte_pt)):
    L.append(int(byte_pt[i])*(m//256))

mat=Matrix(ZZ,10,9)
for i in range(0,8):
    mat[0,i]=pow(a,i,m)
cur=0
for i in range(0,8):
    mat[1,i]=(L[0]*pow(a,i,m) + cur - L[i]) % m
    cur=(cur*a+b)%m
for i in range(0,8):
    mat[2+i,i]=m
mat[1,-1]=W
new_mat=mat.LLL()

for i in range(0,new_mat.nrows()):
    if abs(new_mat[i,8])==W:
        sign = 1 if new_mat[i,8] == W else -1
        k_val = sign * new_mat[i,0]
        break

state_pt = L[0] + k_val

for i in range(0,8):
    state_pt = (state_pt*a+b)%m

key = b''
key += bytes([state_pt >> 40])
for i in range(0,7):
    state_pt = (state_pt*a+b)%m
    key += bytes([state_pt >> 40])


# recover from IV[0:8]
L = []
for i in range(0,len(byte_iv)):
    L.append(int(byte_iv[i])*(m//256))

mat=Matrix(ZZ,10,9)
for i in range(0,8):
    mat[0,i]=pow(a,i,m)
cur=0
for i in range(0,8):
    mat[1,i]=(L[0]*pow(a,i,m) + cur - L[i]) % m
    cur=(cur*a+b)%m
for i in range(0,8):
    mat[2+i,i]=m
mat[1,-1]=W
new_mat=mat.LLL()

for i in range(0,new_mat.nrows()):
    if abs(new_mat[i,8])==W:
        sign = 1 if new_mat[i,8] == W else -1
        k_val = sign * new_mat[i,0]
        break

state_iv = L[0] + k_val
a_inv = inverse_mod(a, m)

for i in range(0,8):
    state_iv = ((state_iv-b)*a_inv)%m

key += bytes([state_iv >> 40])
for i in range(0,7):
    state_iv = (state_iv*a+b)%m
    key += bytes([state_iv >> 40])


iv_bytes = bytes.fromhex(kk['IV'])
pt_bytes = bytes.fromhex(kk['plaintext'])
cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
ct = cipher.encrypt(pt_bytes)

to_send = {"option": "validate", "ciphertext": ct.hex()}
send_json(to_send)
print(recv_json())
