from pwn import *
io=remote('host8.dreamhack.games', 17559)
#io=process(['sage', 'server.py'])
#context.log_level='debug'
#do it like normal padding oracle
def attempt():
    io.sendlineafter(b">> ",b"1")
    kk=io.recvline().decode().strip()
    iv=bytes.fromhex(kk[:32])
    ct=bytes.fromhex(kk[32:64])
    init_iv=iv
    I=b"\x00"*16
    for i in reversed(range(16)):
        pad_val=bytes([16-i])
        for j in range(i+1,16):
            iv=iv[:j]+bytes([I[j]^pad_val[0]])+iv[j+1:]
        att_cnt=0
        while True:
            att_cnt+=1
            if att_cnt>256:
                #too much 
                print("[-] Something went wrong, exiting...")
                return None
            found=False
            for c in range(256):
                print(f"[*] Attempting byte {i} with value {c:02x} (attempt {att_cnt})")
                iv=iv[:i]+bytes([c])+iv[i+1:]
                io.sendlineafter(b">> ",b"2")
                io.sendlineafter(b"> ",(iv+ct).hex().encode())
                res=io.recvline().strip()
                if res==b"True":
                    I=I[:i]+bytes([c^pad_val[0]])+I[i+1:]
                    found=True
                    print(f"[*] Found byte {i}: {I[i]:02x}")
                    break
            if found:
                break
            if(i==0):
                # no bytes else to change
                print("[-] Failed to find a valid padding, exiting...")
                return None
          #change random bytes to create completely new inp  
          hehe=random.randint(0,i-1)
            iv=iv[:hehe]+bytes([random.randint(0,255)])+iv[hehe+1:]
            
    print(f"[*] Found I: {I.hex()}")
    token=bytes(a^b for a,b in zip(I,init_iv))
    print(f"[*] Found token: {token.hex()}")
    return token

x=attempt()    
while(x == None):
    x=attempt()
io.sendlineafter(b">> ",b"3")
io.sendlineafter(b"> ",x.hex().encode())
res=io.recvall().decode()
print(res)
