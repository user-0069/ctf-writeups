import json
import re
from pwn import *
from Crypto.Util.number import isPrime, long_to_bytes, bytes_to_long
from sage.all import *
#context.log_level = 'debug'
#this chall implement el gamal encryption
# flaw 1: generator g and 256 are both quradtic residue, so any power of them is still a quadratic residue
# flaw 2: the author want me = (padding << 1) + m%2, but without parentheses, it runs as me = padding << (1+m%2)
# if we do the math correctly, c2=me*(g^(x*y)) = padding * (g^(x*y)) * 2^(1+m%2)
# note that padding and g are both quadratic residue
# so c2 is qudratic residue if m%2=0, and c2 is quadratic non-residue if m%2=1
# so we can recover the flag bit by bit 
q = 117477667918738952579183719876352811442282667176975299658506388983916794266542270944999203435163206062215810775822922421123910464455461286519153688505926472313006014806485076205663018026742480181999336912300022514436004673587192018846621666145334296696433207116469994110066128730623149834083870252895489152123
g = 104831378861792918406603185872102963672377675787070244288476520132867186367073243128721932355048896327567834691503031058630891431160772435946803430038048387919820523845278192892527138537973452950296897433212693740878617106403233353998322359462259883977147097970627584785653515124418036488904398507208057206926
pattern = re.compile(
    r"\(public_key=(?P<public_key>0x[0-9a-f]+)\)\s*"
    r"\(c1=(?P<c1>0x[0-9a-f]+),\s*c2=(?P<c2>0x[0-9a-f]+)\)"
)

with open("output.txt", "r") as f:
    data = [
        {name: Integer(value[2:], 16) for name, value in match.groupdict().items()}
        for match in pattern.finditer(f.read())
    ]
flag=0
for x in reversed(data):
    if(pow(x['c2'], (q-1)//2, q) == 1):
        flag=flag*2+1
    else:
        flag=flag*2
print(long_to_bytes(flag))
