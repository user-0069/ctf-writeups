## Description
[movingday.py](https://training.bksec.vn/apiv2/files/local/njePAJGdog_5N5SaY6Yjm?iat=1772295000&sig=vwmz2K3y6BThAKrdTKiVciFEipplO9En03UBrRHbA9Y)\
[output.txt](https://training.bksec.vn/apiv2/files/local/hs9DqEC3a9y_n9navFJdd?iat=1772295000&sig=_Xc6lKGUwGZCjtVrdDlZGTe_yJQRlr62csMPgM-pekU)
## Solution
The `find_k` function returned 2 in this problem, meaning that this curve has low embedding degree. It is vulnerable to MOV attack:
* turn a pair of number in $F_p$ into a single integer in $F_{p^2}$ by `weil_pairing` and preserve some mathematical properties.
* The problem "find k such that $k \times P=Q$"(ECDLP problem) is now become "find k such that $u^k=v$" (FFDLP problem) after doing `weil_pairing`.
* get `a` and get the key to recover flag
```
p=935206973510881063
E=EllipticCurve(GF(p), [1, 0])
G=E(920733980303540035, 324806069102286957)
A=E(314432468824764033, 638820118168074289)
B=E(468208591763165369, 798888595329641156)
nonce="c3e9b5756ea7b7ef78dfb7fc"
ct="68e7a5af353191a651e0fe4c6e01c78c720faefffcc1dd2f957897d8167fc8dc4bc3dd2d383d2274c719eb22e7f59fd9645763bbdfb541e7ce0b00a46987612d97a033de6b82ef84cadf6477a860b400cbaf8b5f8c41f86e49e3ac0955"
tag="bf68759410b44912d02fb04e12b9a846"
primes = E.order().factor()
q_order = max(primes)[0]
F2=GF(p**2, 'a')
E2=EllipticCurve(F2, [1, 0])   
R=E2(0)        
G2=E2(G)
A2=E2(A)
B2=E2(B)
while R == E2(0) or G2.weil_pairing(R, q_order) == 1:
    R = E2.random_point()
    m = R.order()
    d = gcd(m, q_order)
    R = (m // d) * R
u=G2.weil_pairing(R, q_order)
v=A2.weil_pairing(R, q_order)
v_pari = pari(v)
u_pari = pari(u)
n_pari = pari(q_order)

a = int(v_pari.fflog(u_pari, n_pari))
S=a*B
S_x = Integer(S[0])
key = hashlib.sha256(long_to_bytes(S_x)).digest()
cipher=AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(nonce))
pt=cipher.decrypt_and_verify(bytes.fromhex(ct), bytes.fromhex(tag))
print(pt.decode())
```
```
BKSEC{sUp3Rs1nGU1aR_cURv3s_mAY_s0unD_k3w1_BUT_D0_N0T_US3_TH3M_W1TH_L0W_3MB3DDING_D3GREEEE!!!}
```
