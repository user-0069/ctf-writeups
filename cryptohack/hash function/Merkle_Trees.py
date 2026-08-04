from hashlib import sha256
from Crypto.Util.number import long_to_bytes

def hash256(data):
    return sha256(data).digest()

def merge_nodes(a, b):
    return hash256(a + b)

binary_flag = ""

with open("output.txt", "r") as f:
    for line in f:
        chal = eval(line)

        a = bytes.fromhex(chal[0])
        b = bytes.fromhex(chal[1])
        c = bytes.fromhex(chal[2])
        d = bytes.fromhex(chal[3])
        root = chal[4]
        
        left = merge_nodes(a, b)
        right = merge_nodes(c, d)
        actual_root = merge_nodes(left, right).hex()
        
        if actual_root == root:
            binary_flag += "1"
        else:
            binary_flag += "0"

flag_bytes = long_to_bytes(int(binary_flag, 2))
print(flag_bytes.decode())
