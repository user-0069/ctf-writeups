from hamiltonicity import *
from pwn import *
import json
io=remote('archive.cryptohack.org', 14635)
def send_json(dict):
    io.sendline(json.dumps(dict).encode())
def recv_json():
    return json.loads(io.recvline().decode())
io.recvuntil(b'cycle!')
N = 5
G = [
        [0,0,1,0,0],
        [1,0,0,0,0],
        [0,1,0,0,0],
        [0,0,0,0,1],
        [0,0,0,1,0]
    ]
#we can't pass the pedersen without the knowledge of the secret if the challenge bit is truly random
#so we force the challenge bit to be 0
#bit 0 is showing the permutation, while bit 1 is showing the hamiltonian cycle.

state=b''
for i in range(128):
    while True:
        # generate a permuted graph
        perm=random.sample(range(N),N)
        g_perm=permute_graph(G,N,perm)
        
        #commit to that graph
        G2, openings = commit_to_graph(g_perm,N)
        
        #precalculate the challenge bit  
        next_state = hash_committed_graph(G2, state, comm_params)
        chall_bit=next_state[-1] & 1
        #only send proof when the bit is 0, otherwise try another permutation
        if chall_bit == 0:
            state=next_state
            send_json({'A': G2, 'z': [perm,openings]})
            print(f"attempt {i}:")
            print(io.recvline())
            break
print(io.recvall())




