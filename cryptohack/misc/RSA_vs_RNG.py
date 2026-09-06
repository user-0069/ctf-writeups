import json
from pwn import *
from Crypto.Util.number import isPrime, long_to_bytes, bytes_to_long
from sage.all import *
context.log_level = 'debug'
#we can write q in the form q=A^n*p + B*(A^(n-1)) + B*(A^(n-2)) + ... + B*(A^0)) = a*p +b
#then N=p*q = p*(a*p + b) = a*p^2 + b*p
#p is a root of the polynomial f(x)=a*x^2 + b*x - N
#we've done factoring N! just get the flag 
MOD = 2**512
A = 2287734286973265697461282233387562018856392913150345266314910637176078653625724467256102550998312362508228015051719939419898647553300561119192412962471189
B = 4179258870716283142348328372614541634061596292364078137966699610370755625435095397634562220121158928642693078147104418972353427207082297056885055545010537
dict={"N": 95397281288258216755316271056659083720936495881607543513157781967036077217126208404659771258947379945753682123292571745366296203141706097270264349094699269750027004474368460080047355551701945683982169993697848309121093922048644700959026693232147815437610773496512273648666620162998099244184694543039944346061, "E": 65537, "ciphertext": "04fee34327a820a5fb72e71b8b1b789d22085630b1b5747f38f791c55573571d22e454bfebe0180631cbab9075efa80796edb11540404c58f481f03d12bb5f3655616df95fb7a005904785b86451d870722cc6a0ff8d622d5cb1bce15d28fee0a72ba67ba95567dc5062dfc2ac40fe76bc56c311b1c3335115e9b6ecf6282cca"}
N=dict["N"]
E=dict["E"]
ciphertext=dict["ciphertext"]
R=Zmod(MOD)
A=R(A)
B=R(B)
P=PolynomialRing(R, 'x')
x = P.gen()
a=R(1)
b=R(0)
for i in range(1, 300):
    print(f"Trying i={i}")
    a=a*A
    b=b*A+B
    f=a*(x**2)+b*x-R(N)
    roots = f.roots(multiplicities=False)
    for root in roots:
        p = int(root)
        if isPrime(p) and N % p == 0:
            q = N // p
            phi = (p - 1) * (q - 1)
            d = inverse_mod(E, phi)
            c = int(ciphertext, 16)
            m = pow(c, d, N)
            plaintext = long_to_bytes(m)
            print(f"flag: {plaintext}")
            exit()
