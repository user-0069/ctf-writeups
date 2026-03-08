## Phân tích
Với $N$ là 1 moduli RSA thì $N-\phi(N) =p + q - 1$. Đặt $X=p+q-1$. $X$ sẽ có 512 hoặc 513 bit. Kiểu dữ liệu `int` của Python chỉ lưu được khoảng 4300 kí tự, 
nghĩa là $10^{4300}$. Nếu ta cho `e` $> 10^{4300} / X$ thì server sẽ trả về lỗi `ERR: ...`. Ta thực hiện chặt nhị phân để tìm $X$, hoàn toàn có thể như sau:
* Search space của X là $[2^{512},2^{513}]$ , có độ lớn $2^{512}$
* Sau khi thực hiện chặt nhị phân 500 lần, độ lớn còn lại của search space còn khoảng $2^{14}$, bruteforce được nốt
* Ở bước bruteforce thì chuyển về dạng tìm $p,q$ biết $N =pq$ và $p+q$, rồi giải RSA một cách đơn giản

Lời giải có thể áp dụng cho bài ZKRSA
## Code
```
from pwn import remote
from sage.all import *
from random import Random
from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot

r = remote('100.64.0.66' ,31900)
recv = r.recvuntil(b"secured\n").decode()
print(recv)
kk=r.recvline().strip().decode()
print(kk)
N=int(kk)
C=10**4300
L=2**512
R=2**513
for i in range(500):
    kk=r.recvuntil(b"ME!!! ").decode()
    mid=(L+R)//2 
    payload = str(-(C//mid))
    r.sendline(payload)
    kk=r.recvline().strip().decode()
    print(kk,i)
    if("ERR" in kk):
        L=mid
    else:
        R=mid
for i in range(L,R+1):
    kk=iroot((i+1)**2-4*N,2)
    if kk[1]:
        p=(kk[0]+i+1)//2
        q=i+1-p
        if p*q==N:
            print("p=",p)
            print("q=",q)
            break
kk=r.recvall().strip().decode()
phi=(p-1)*(q-1)
e=65537
d=inverse_mod(e,phi)
c=int(kk.split("\n")[-1],10)
m=pow(c,d,N)
print(long_to_bytes(int(m)))

```
## Cảm xúc
Lần đầu gặp bài lợi dụng lỗi của Python 0_0. AI đã phải thuyết phục tôi "thinking outside the box" vì tôi không tin lời giải lại có thể như vậy.



