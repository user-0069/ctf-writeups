from hashlib import sha256
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from sage.all import *
from pwn import *
import json
def send_json(io,data):
    io.sendline(json.dumps(data).encode())
def recv_json(io):
    return json.loads(io.recvline().decode())
def hash256(data):
    return sha256(data).digest()
def merge_nodes(a, b):
    return hash256(a+b)
leaf = [b""] * 8
#this chall is about merkle tree
#the goal of this chall is to gather all infomation about the leaf nodes, using only 1 get_node request

#collect info about the leaf[3:8] first (the flag part that is fixed, stay unchanged among connections)
for i in range(3, 8):
    io=remote("socket.cryptohack.org", 13432)
    print(io.recvline())
    to_send={"option":"get_node","node":i}
    send_json(io,to_send)
    kk=recv_json(io)
    leaf[i]=bytes.fromhex(kk["msg"])
    io.close()
node_c=merge_nodes(leaf[4], leaf[5])
node_d=merge_nodes(leaf[6], leaf[7])
att=0
io=remote("socket.cryptohack.org", 13432)
io.recvline()
#flag is 47 bytes long, so the randomized part is 17 bytes long
#get the last node of self.nodes[0], which contain self.nodes[1][0], represent the first 16 bytes
to_send={"option":"get_node","node":-1} #get len(nodes[0])-1 is forbidden, so we use -1 instead
send_json(io,to_send)
kk=recv_json(io)
node_a=bytes.fromhex(kk["msg"])
#there are 17 randomized bytes in total , so the last one bytes we need to bruteforce
for i in range(256):
    print(i)
    leaf[2]=hash256(bytes([i])+b"crypto{")
    node_b=merge_nodes(leaf[2], leaf[3])
    root=merge_nodes(merge_nodes(node_a, node_b), merge_nodes(node_c, node_d))
    to_send={"option":"do_proof","root":root.hex()}
    send_json(io,to_send)
    kk=recv_json(io)
    if "failed" not in kk["msg"]:
        print(kk["msg"])
        break




   





