from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import *
from hashlib import sha1
from sage.all import *
from pwn import *
import json
def send_json(data):
    io.sendline(json.dumps(data).encode())
def recv_json():
    return json.loads(io.recvline().decode())
io = remote("socket.cryptohack.org", 13387)
#This chall is about dual_EC_DRBG
#nothing stop us from putting P=Q
#the RNG returns the x coordinate of the point r*P, where r is the internal state,keeping its last 240 bits
#because x is bounded by 2**256, so the first missing 16 bits could be bruteforced
#We gether the first 2 states, bruteforce the first 16 bits of the first state, to check whether that is the true firts state
#after that we simulate all the game rounds and get the flag

#sec256pr1 curve param
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
EC = EllipticCurve(GF(p), [a, b])

casino_x = "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
casino_y = "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
P=EC(casino_x,casino_y)
print(io.recvline())
to_send={"x":casino_x,"y":casino_y}
send_json(to_send)
kk=recv_json()
print(kk)
states=[]
cur_state=0
cur_round=0
#gather 2 states
while len(states) <2:
    to_send={"choice": "BLACK"}
    send_json(to_send)
    kk=recv_json()
    print(kk)
    cur_state=37*cur_state+kk["spin"]
    cur_round=kk["round"]
    if("croupier" in kk["msg"]):
        states.append(cur_state)
        cur_state=0
def next(state):
    state=int((state*P).xy()[0])
    return state
#find the true first state
for i in range(2**16):
    if(next(i*2**240+states[0])%(2**240)==states[1]):
        print("Found seed:",i*2**240+states[0])
        seed=i*2**240+states[0]
        break
 #create the spin list   
spin_list=[]
while(len(spin_list)<150):
    cur_state=[]
    num=seed%(2**240)
    while(num>0):
        cur_state.append(num%37)
        num//=37
    spin_list=spin_list+cur_state[::-1]
    seed=next(seed)
#finish the rounds
for i in range(cur_round-1,125):
    to_send={"choice": spin_list[i]}
    print(to_send)
    send_json(to_send)
    kk=recv_json()
    print(kk)

