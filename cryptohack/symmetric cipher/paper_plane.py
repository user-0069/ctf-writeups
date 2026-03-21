
from pwn import *
import json
import requests
from string import printable
BASE_URL="https://aes.cryptohack.org"
def checkpad(ct,m0,c0):
    url = f"{BASE_URL}/paper_plane/send_msg/{ct}/{m0}/{c0}/"
    kk=requests.get(url)
    return kk.json()
def get_ct():
    url = f"{BASE_URL}/paper_plane/encrypt_flag/"
    kk=requests.get(url)
    return kk.json()
def hexify(kk):
    ctt = "".join("{:02x}".format(z) for z in (kk))
    return ctt
kk=get_ct()
c0=kk["c0"]
m0=kk["m0"]
c1=kk["ciphertext"][:32]
c2=kk["ciphertext"][32:]
c0=bytes.fromhex(c0)
m0=bytes.fromhex(m0)
c1=bytes.fromhex(c1)
c2=bytes.fromhex(c2)


c0_list=[int(z) for z in c0]
c1_list=[int(z) for z in c1]
m0_list=[int(z) for z in m0]
c2_list=[int(z) for z in c2]
pot=string.ascii_lowercase+string.digits+"_}{!?" 
for i in range(1,17):
    pot+=chr(i)
pot+=string.ascii_uppercase
#only consider possble plaintext in pot -> faster runtime
print(pot)
# just like classic padding oracle, modify c0 until getting good padding
I=[0]*16
m1_list=[]
for i in reversed(range(16)):
    val_pad=16-i 
    temp=c0_list[:]
   
    for j in range(i+1,16):
        temp[j] = I[j] ^ val_pad 
    if i == 15:
        temp[14] ^= 1 # try to avoid the case where the second last byte 0x02, combining with a wrong last byte 0x02 and return a fake good padding
    for j in pot:
        char=c0_list[i]^ord(j)^val_pad
        temp[i]=char
        lmao=checkpad(hexify(c1_list),hexify(m0_list),hexify(temp))
        if("msg" in lmao ):
            I[i]=char^val_pad
            print(f"byte {i} is {chr(I[i]^c0_list[i])}")
            m1_list=[ord(j)]+m1_list
            prev=j
            break

I=[0]*16
m2_list=[]
prev=""
for i in reversed(range(16)):
    val_pad=16-i 
    temp=c1_list[:]
    for j in range(i+1,16):
        temp[j] = I[j] ^ val_pad
    if i == 15:
        temp[14] ^= 1
    for j in prev+pot: # speedup with multiple padding char
        char=c1_list[i]^ord(j)^val_pad
        temp[i]=char
        lmao=checkpad(hexify(c2_list),hexify(m1_list),hexify(temp))
        if("msg" in lmao ):
            I[i]=char^val_pad
            print(f"byte {i} is {chr(I[i]^c1_list[i])}")
            m2_list=[ord(j)]+m2_list
            prev=j
            break

print("".join([chr(z) for z in (m1_list+m2_list)]))
# crypto{h3ll0_t3l3gr4m} 
# Telegram does use IGE !


        







