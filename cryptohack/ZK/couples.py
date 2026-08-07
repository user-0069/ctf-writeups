from py_ecc.optimized_bn128 import G1, G2, multiply, pairing, is_on_curve, b, FQ, curve_order
from hashlib import sha256
import os
from pwn import *
from sage.all import *
import json
context.log_level = 'debug'
io=remote("socket.cryptohack.org", 13415)
def send_json(data):
    io.send(json.dumps(data))
def recv_json():
    return json.loads(io.recvline().decode())

#this ultimate goal of this challenge is letting pairing(xzH,G1)==pairing(H',xzG)
#what happen if we set z=0? then pairing(xzH,G1)==pairing(H',xzG)==pairing(0,G1)==pairing(H',0)==1
#how do we set z=0?
#in function set_internal_z, new_z=inverse(poly(z,x),p), such that x*new_z !=1 mod p 
#in normal inverse() function, inverse(0,p) should return error, however this custom inverse() does not
#inverse(0,p)=0 here
#we only need to somehow let poly(z,x)=0 then we are done
#how?
#poly(z,x)=x^(z+7)-x^3=x^3*(x^(z+4)-1)
#Aha, if z+4=phi(p)=p-1, then poly(z,x)=0
#so we need to set z=p-5, done!!!
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
io.recvline()
to_send={"option":"set_internal_z","z":hex(p-5)}
send_json(to_send)
io.recvline()
to_send={"option":"do_proof","G":str(G1),"hsh":hex(134)}
send_json(to_send)
io.recvline()
