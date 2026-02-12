## Description
[chall.py](https://training.bksec.vn/apiv2/files/local/HJPG1aEMBIOitffGNJ735?iat=1770736200&sig=GsNNa8L3uXkAq_-6aDLbLYOL0MB1QrM1qmS_d-KgmdU)\
`nc 103.77.175.40 7001`
## My solution
I spam `nc` to get `len(flag)` (given) and `len(key)` (max of the `pivot`s we get).
Im pretty sure that the last character of the base64 encoded flag is '=', so I spam again to recover the characters of the key:
```
lenkey=50
lenflag=96
key=[0]*100
cnt=0
while cnt<lenkey:
    r=remote("103.77.175.40", 7001)
    data=r.recvall().strip()
    pivot=data[1]
    lenflag=data[0]
    print(data)
    idx=(pivot+lenflag-1)%lenkey
    if(key[idx]==0):
        cnt+=1
    key[idx]=data[-1]^ord("=")
    r.close()
```
```
lenkey=50
lenflag=96
key=[73, 95, 98, 101, 116, 95, 121, 111, 117, 95, 99, 111, 117, 108, 100, 95, 110, 111, 116, 95, 102, 105, 110, 100, 95, 116, 104, 101, 95, 107, 101, 121, 46, 95, 67, 104, 97, 110, 103, 101, 95, 109, 121, 95, 109, 105, 110, 100, 33, 33]
key=[chr(k) for k in key]
key="".join(key)
print(key)
```
Nice key:
```
I_bet_you_could_not_find_the_key._Change_my_mind!!
```
Knowing the key, everything become easy:
```
key=b"I_bet_you_could_not_find_the_key._Change_my_mind!!"
r=remote("103.77.175.40", 7001)
data=r.recvall().strip()
pivot=int(data[1])
data=data[2:]
for i in range(len(data)):
    c=chr(data[i]^key[(pivot+i)%len(key)])
    print(c,end="")
```
This must be the flag in base64 (end with a '=')
```
QktTRUN7OWI3ODU0OWRkOTY0Yzg1MjA4ZDM2YTUyYmUwZjExYmNiM2QyNDBiODg3YjIxYTZiNzUwOTFmYzVkNDFiMWFkZn0=
```
```
base64_flag="QktTRUN7OWI3ODU0OWRkOTY0Yzg1MjA4ZDM2YTUyYmUwZjExYmNiM2QyNDBiODg3YjIxYTZiNzUwOTFmYzVkNDFiMWFkZn0="
flag=base64.b64decode(base64_flag)
print(flag)
```
Here it is:
```
base64_flag="QktTRUN7OWI3ODU0OWRkOTY0Yzg1MjA4ZDM2YTUyYmUwZjExYmNiM2QyNDBiODg3YjIxYTZiNzUwOTFmYzVkNDFiMWFkZn0="
flag=base64.b64decode(base64_flag)
print(flag)
```
```
b'BKSEC{9b78549dd964c85208d36a52be0f11bcb3d240b887b21a6b75091fc5d41b1adf}'
```





