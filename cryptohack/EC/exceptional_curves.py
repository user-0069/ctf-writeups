from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from random import randint
import hashlib
import os
from sage.all import *


# Use smart attack to solve ECDLP#
def smart_attack(P, Q, p):
    
    E = P.curve()
    
    # EC on Qp
    Eqp = EllipticCurve(Qp(p, 2), [a, b])

    # p-adic liftting
    P_Qp = Eqp.lift_x(ZZ(P.xy()[0]))
    Q_Qp = Eqp.lift_x(ZZ(Q.xy()[0]))

    # ensure the correct sign of the lifted points (lift_x can return -P or P)
    if P_Qp.xy()[1] % p != P.xy()[1]: 
        P_Qp = -P_Qp
    if Q_Qp.xy()[1] % p != Q.xy()[1]: 
        Q_Qp = -Q_Qp

    p_times_P = p * P_Qp
    p_times_Q = p * Q_Qp        

    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()

    # p-adic logarithm: phi(P) = -(x / y)
    phi_P = -(x_P / y_P)
    phi_Q = -(x_Q / y_Q)

    # find k such that phi(Q) = k * phi(P)
    k = phi_Q / phi_P
    
    return ZZ(k) % p
# Curve params
p = 0xa15c4fb663a578d8b2496d3151a946119ee42695e18e13e90600192b1d0abdbb6f787f90c8d102ff88e284dd4526f5f6b6c980bf88f1d0490714b67e8a2a2b77
a = 0x5e009506fcc7eff573bc960d88638fe25e76a9b6c7caeea072a27dcd1fa46abb15b7b6210cf90caba982893ee2779669bac06e267013486b22ff3e24abae2d42
b = 0x2ce7d1ca4493b0977f088f6d30d9241f8048fdea112cc385b793bce953998caae680864a7d3aa437ea3ffd1441ca3fb352b0b710bb3f053e980e503be9a7fece

# Define curve
E = EllipticCurve(GF(p), [a, b])

#params
G = E(3034712809375537908102988750113382444008758539448972750581525810900634243392172703684905257490982543775233630011707375189041302436945106395617312498769005 , 4986645098582616415690074082237817624424333339074969364527548107042876175480894132576399611027847402879885574130125050842710052291870268101817275410204850 )
pub=E(4748198372895404866752111766626421927481971519483471383813044005699388317650395315193922226704604937454742608233124831870493636003725200307683939875286865 , 2421873309002279841021791369884483308051497215798017509805302041102468310636822060707350789776065212606890489706597369526562336256272258544226688832663757 )
b_x = 0x7f0489e4efe6905f039476db54f9b6eac654c780342169155344abc5ac90167adc6b8dabacec643cbe420abffe9760cbc3e8a2b508d24779461c19b20e242a38
b_y = 0xdd04134e747354e5b9618d8cb3f60e03a74a709d4956641b234daa8a65d43df34e18d00a59c070801178d198e8905ef670118c15b0906d3a00a662d3a2736bf
B = E(b_x, b_y)
data={'iv': '719700b2470525781cc844db1febd994', 'encrypted_flag': '335470f413c225b705db2e930b9d460d3947b3836059fb890b044e46cbb343f0'}

#sign of smart attack
assert (E.order()==p) #true

# ECDLP
n=smart_attack(G, pub, p)
shared_secret = (n * B).xy()[0]
sha1=hashlib.sha1(str(shared_secret).encode('ascii')).digest()
key = sha1[:16]
cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(data['iv']))
encrypted_flag = bytes.fromhex(data['encrypted_flag'])
flag = unpad(cipher.decrypt(encrypted_flag), AES.block_size)
print(flag.decode())
