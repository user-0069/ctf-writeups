# Vote for Pedro
## Description
[RSA challenges](https://cryptohack.org/challenges/rsa/)
## My solution
Set $A$ = `long_to_bytes(b'\00'+b'VOTE FOR PEDRO')`. We need to find $B$ such that $B^3 \equiv A + x.2^k {mod}(N)$ ($k$ is the `bit_length()`
of $A$).\
Let's assume $x,B$ are small enough compared to $N$ and satisfy $A + x.2^k = B^3$. The goal here is to find $B < 2^k$ that $B^3 \equiv A {mod}(2^k)$.
We "build" $B$ as follows:
* iterate through k bits from low to high.
* changing the $i$-th bit of $B$ only affect the $i$-th bit and higher bits of $B^3$, so choosing the $i$-th bit of $B$ depends
on whether the $i$-th bit of $B^3$ matches the $i$-th bit of $A$ or not.
* Choose apppriate $i$-th bit and move on the higher bits.
```
target=b"\x00"+b'VOTE FOR PEDRO'
N = 22266616657574989868109324252160663470925207690694094953312891282341426880506924648525181014287214350136557941201445475540830225059514652125310445352175047408966028497316806142156338927162621004774769949534239479839334209147097793526879762417526445739552772039876568156469224491682030314994880247983332964121759307658270083947005466578077153185206199759569902810832114058818478518470715726064960617482910172035743003538122402440142861494899725720505181663738931151677884218457824676140190841393217857683627886497104915390385283364971133316672332846071665082777884028170668140862010444247560019193505999704028222347577
e = 3
k=len(target)*8
A=bytes_to_long(target)
B=0
res=0
for i in range(k):
    bit=1<<i
    res_1=res|bit
    cube=(res_1)**e
    if((cube&bit)==(A&bit)):
        res=res_1
r.recvline()
to_send={
    "option":"vote",
    "vote":long_to_bytes(res).hex()
}
send(to_send)
print(recv())
```
```
{'flag': 'crypto{y0ur_v0t3_i5_my_v0t3}'}
```

