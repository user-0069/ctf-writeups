from sage.all import *
from pwn import *
from ast import literal_eval
import json

io = remote("socket.cryptohack.org", 13390)
# the idea that after we reset the a almost stay the same, with the change of only 1 bit with 50%
#after reset, the state repeats again and again, except for the part after seed(getrandbits), changing at most 1 bit of a
#so we can easily do reset->get_sample reset->get sample and wait until 2 states differ in only 1 bit
#by then we can get flag[i]=(b1-b2)/(a1-a2) mod q
#repeat until we get the whole flag

# another natural idea is just use classic LLL like previous problems
q=127

def send_json(data):
    io.sendline(json.dumps(data).encode())

def recv_json():
    return json.loads(io.recvline().decode())

io.recvline()
flag= "?"*100
n=5
while True:
    send_json({"option": "reset"})
    recv_json()
    send_json({"option": "get_sample"})
    kk1=recv_json()
    send_json({"option": "reset"})
    recv_json()
    send_json({"option": "get_sample"})
    kk2=recv_json()
    a1=kk1['a']
    b1=kk1['b']
    a2=kk2['a']
    b2=kk2['b']
    delta_a=0
    n=len(a1)
    diff_indices = [j for j in range(n) if a1[j] != a2[j]]
    if len(diff_indices) != 1:
        continue
    j = diff_indices[0]
    if(a1[j]!=a2[j]):
        flag=flag[:j]+str(chr((b1-b2+q)%q*inverse_mod(a1[j]-a2[j]+q, q)%q))+flag[j+1:]
    print(flag[:n])
    if("?" not in flag[:n]):
        break
