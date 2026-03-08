## Phân tích
```
from secrets import randbits
from Crypto.Util.number import *
  
flag = bytes_to_long(b"BKSEC{fake_flag}") # you lose aura if you submit this... (we are watching)

B = 1 << 256

def r256():
    x = randbits(256) | (1 << 255) | 1  
    return x

while True:
    x, y = r256(), r256()
    p = x * B + y       
    q = y * B + x       
    if isPrime(p) and isPrime(q):
        break

e = 65537
N = p * q
c = pow(flag, e, N)

print(f"{N = }")
print(f"{e = }")
print(f"{c = }")
```
Dựa vào đoạn code, ta thấy $N= (x.B +y)(y.B+x) = x.y.B^2 + B.(x^2 + y^2)+ x.y$. Vì $B \approx 2^{256}$ nên (có vẻ) không thể trực tiếp tính $xy, x^2 + y^2$ ($B$ không đủ to).\
Ở đây mình đi tính $xy$: chia $xy$ thành 2 nửa: 256 bit đầu và 256 bit sau
* 256 bit sau thì khá đơn giản: $xy \pmod{B}=N \pmod{B}$
* với 256 bit đầu: ta nhận thấy $B.(x^2 + y^2)+ x.y < 2. B^3$ vậy 256 bit đầu của $N$ cũng gần tương tự 256 bit đầu của $x.y$ hay ($x.y.B^2$)
Tìm được $xy$ thì cũng tìm được $x^2+y^2$ rồi suy ra tổng và hiệu, từ đó tìm được p,q và giải mã RSA.
## Code
```

from gmpy2 import is_square,iroot
from Crypto.Util.number import long_to_bytes, isPrime
N = 107444638859099155759777187090231262569833054720517547475456101236477286061642951211232522980016935214117151901316067288134076019258357378153815894696105422994651894516549086845637403949534145390050746353299397783409065996987527927026314423191436300386280922075865669873754956335784354470237039709346406222789
e = 65537
c = 56143710973900761339774002971192037727375234874650436422245945684342980716505499471085786012340621409106405319356586450688993792522513823502401085339774194961300841598824881056390845294225756335102709315028822707701848497421372062559501439381841852116763699839771135406441292657937478625029095325072727620068
B=1<<256
first_half=N//(B**3) -1
second_half=N%B
xy=first_half*B+second_half
sum_square=(N-xy*(B*B+1))//B
sum=iroot(sum_square+2*xy,2)[0]
diff=iroot(sum_square-2*xy,2)[0]
print(iroot(sum_square+2*xy,2))
print(iroot(sum_square-2*xy,2))
x=(sum+diff)//2
y=(sum-diff)//2
p=x*B+y
q=y*B+x
phi=(p-1)*(q-1)
d = pow(e, -1, phi)
m = pow(c, d, N)
print(long_to_bytes(m))
```
## Cảm xúc
Bài duy nhất mình không dùng AI (•_•)...

