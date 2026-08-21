
## Challenge
In this challenge, we interact with a server that encrypts the bits of a secret flag one by one. The server uses a giant modulus $N$, which is stated to be the product of 16 safe primes. 

For each bit index $i$, the server responds differently depending on the value of the bit:
*   **If the bit is 1:** It returns $c \equiv g^r \pmod N$ (where $r$ is a random integer).
*   **If the bit is 0:** It returns $c \equiv \text{randint}(1, N-1) \pmod N$ (pure random noise).

Our goal is to distinguish the mathematically structured 1-bits from the purely random 0-bits to recover the flag.

## Vulnerability

The vulnerability lies in the structure of the modulus $N$. $N$ is the product of 16 safe primes, meaning each prime factor is of the form $p_i = 2q_i + 1$, where $q_i$ is also a massive prime.

Euler's totient function for $N$ is:
$$\phi(N) = (p_1 - 1)(p_2 - 1)\dots(p_{16} - 1) = 2^{16} \cdot (q_1 \cdot q_2 \dots q_{16})$$

Notice the group order consists of a massive prime-order subgroup $\prod q_i$, and a tiny $2^{16}$ **cofactor**. We can isolate this cofactor by raising the ciphertext to the power of the massive prime subgroup. 

Let our exponent be $Q = \phi(N) // 2^{16}$.

### Analyzing a 1-Bit
For a 1-bit, the ciphertext is $c = g^r$. 
If we raise it to the power of $Q$, we get:
$$c^Q \equiv (g^r)^Q \equiv (g^Q)^r \pmod N$$

Let's define $K \equiv g^Q \pmod N$. Because $2Q$ is a multiple of $p_i - 1$ for all prime factors, $K^2 \equiv g^{2Q} \equiv 1 \pmod N$. 
Because $K^2 = 1$, the expression $K^r$ has only two possible outcomes:
*   If $r$ is even: $K^{\text{even}} \equiv 1 \pmod N$
*   If $r$ is odd: $K^{\text{odd}} \equiv K \pmod N$

Therefore, a 1-bit will **always** collapse to either $1$ or $K$.

### Analyzing a 0-Bit
For a 0-bit, the ciphertext $c$ is completely random. 
By the Chinese Remainder Theorem, taking a random number to the power of $Q$ will scatter it randomly across one of the $2^{16}$ (65,536) possible square roots of $1$ modulo $N$. 

The probability that a 0-bit accidentally lands on exactly $1$ or $K$ is incredibly small ($2 / 65536$). 

## The Exploit
We simply connect to the server, ask for each bit, and calculate $c^Q \pmod N$. If the result is $1$ or $K$, we record a `1`. Otherwise, we record a `0`.

### Script

```python
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from sage.all import *
from pwn import *
import json
# context.log_level = 'debug'
def send_json(data):
    io.sendline(json.dumps(data).encode())
def recv_json():
    return json.loads(io.recvline().decode())
io=remote("socket.cryptohack.org", 13398)

N = 56135841374488684373258694423292882709478511628224823806418810596720294684253418942704418179091997825551647866062286502441190115027708222460662070779175994701788428003909010382045613207284532791741873673703066633119446610400693458529100429608337219231960657953091738271259191554117313396642763210860060639141073846574854063639566514714132858435468712515314075072939175199679898398182825994936320483610198366472677612791756619011108922142762239138617449089169337289850195216113264566855267751924532728815955224322883877527042705441652709430700299472818705784229370198468215837020914928178388248878021890768324401897370624585349884198333555859109919450686780542004499282760223378846810870449633398616669951505955844529109916358388422428604135236531474213891506793466625402941248015834590154103947822771207939622459156386080305634677080506350249632630514863938445888806223951124355094468682539815309458151531117637927820629042605402188751144912274644498695897277
phi = 56135841374488684373258694423292882709478511628224823806413974550086974518248002462797814062141189227167574137989180030483816863197632033192968896065500768938801786598807509315219962138010136188406833851300860971268861927441791178122071599752664078796430411769850033154303492519678490546174370674967628006608839214466433919286766123091889446305984360469651656535210598491300297553925477655348454404698555949086705347702081589881912691966015661120478477658546912972227759596328813124229023736041312940514530600515818452405627696302497023443025538858283667214796256764291946208723335591637425256171690058543567732003198060253836008672492455078544449442472712365127628629283773126365094146350156810594082935996208856669620333251443999075757034938614748482073575647862178964169142739719302502938881912008485968506720505975584527371889195388169228947911184166286132699532715673539451471005969465570624431658644322366653686517908000327238974943675848531974674382848
g = 986762276114520220801525811758560961667498483061127810099097
K=pow(g,phi//(2**16),N)
flag=""
cur=0
cnt=0
io.recvline()
while True:
    print("cnt:",cnt)
    to_send={"option": "get_bit","i":cnt}
    send_json(to_send)
    kk=recv_json()
    if("error" in kk):
        break
    c=int(kk["bit"],16)
    if(pow(c,phi//(2**16),N) ==1 or pow(c,phi//(2**16),N) == K):
        cur^=1<<(cnt%8)
    cnt+=1
    if(cnt%8==0):
        print(chr(cur))
        flag+=chr(cur)
        cur=0
    
print(flag)

```
