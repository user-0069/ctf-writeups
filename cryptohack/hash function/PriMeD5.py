
from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import *
io=remote("socket.cryptohack.org", 13392)
import json
#context.log_level='debug'
def sendjson(data):
    io.sendline(json.dumps(data))
def jsonrecv():
    return json.loads(io.recvline().strip())
# a pair of prefix (md5(a1)=md5(a2))
prefix1="4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2"
prefix2="4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2"
a1=int(prefix1,16)
a2=int(prefix2,16)
cnt=0
while(True):
    x=randint(1,2**512//31)
    rem=31-(a1*2**512)%31
    if(is_prime(x*31+rem+a2*2**512)):
        break
    #print(cnt)
    cnt += 1
a1=a1*2**512+x*31+rem
a2=a2*2**512+x*31+rem
#we have md5(a1)=md5(a2)-> md5(a1||k)=md5(a2||k) for any k
# forge k so that a2||k is prime and a1||k is a multiple of 31 (this part is to make the msg shorter than 1024 bytes by setting a=31)
io.recvline()
to_send={"option":"sign","prime":str(a2)} #a2 passed the primility check
sendjson(to_send)
kk=jsonrecv()
sig=kk["signature"]
# there is no primility test in check option, so we can pass a1||k which is a multiple of 31 and the signature will be valid since md5(a1||k)=md5(a2||k)   
to_send={"option":"check","prime":str(a1),"signature":sig,"a":31} # 31 is enough for the flag?
sendjson(to_send)
kk=jsonrecv()
print(kk) #crypto{MD5_5uck5_p4rt_tw0}
