## Description
[gen.py](https://training.bksec.vn/apiv2/files/local/dYal21xbw4hxyHafmZ3N-?iat=1772073000&sig=iTOzMVDYJ2SMNQ7T0Cj6IAQg7yRd8LGpC5Hu_1ZRR08)\
[output.txt](https://training.bksec.vn/apiv2/files/local/cp2lFAsD5JITWBJ9FK0dw?iat=1772073000&sig=9NmHfB06tJC72e1gfMc-judGivuoASgTb4vMYhUXksw)
## My solution
We can easily figure out the `taps` by bruteforce all posible tuples, and double-check with the output. Denote `taps` as $[i_0,i_1,i_2,i_3]$, we have: 
$s_{i_0} \bigoplus s_{i_1} \bigoplus s_{i_2} \bigoplus s_{i_3}=s_{new}$, which is equivalent to: $s_{i_0}=s_{i_1} \bigoplus s_{i_2} \bigoplus s_{i_3}\bigoplus s_{new}$. 
Thats mean we can recover the popped bits from the current state knowing `taps`:
```
n=29*8
taps=[0,0,0,0]
c="10111100111101010011000100001001000001101011010100100110100001001110111101010010111011000110001011010001100011110110110010110111111011110010100100101100110000001100100111011010011011101010000100111111001100011110001100110101011011010111000011101101100000100101110110111000010110111011101110010111001001000110001001110110011100000010010111000101011000001010000110110000110010111110111010100000010010010110000111101100101000001111010000010100001010010011011110101010111111110011111000011011001000010101"
for i in itertools.combinations(range(n),4):
    can=1
    for j in range(n,len(c)):
        expected=0
        for k in i:
            expected^=int(c[j-n+k])
        if expected!=int(c[j]):
            can=0
            break
    if can:
        taps=[i[0],i[1],i[2],i[3]]
        break
print(taps)
c=c[:n]
taps=taps+[n]
first=taps[0]
taps=[i-first-1 for i in taps]
taps.pop(0)
for i in range(29*20):
    new=0
    for j in taps:
        new^=int(c[j])
    c=str(new)+c
c=c[:29*8]
c=int(c,2)
print(long_to_bytes(c))
```
```
BKSEC{may_be_this_is_a_hint?}
```
        

