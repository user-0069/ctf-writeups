from pwn import *
import re
import string
import zlib
import base64
#context.log_level = "debug"
#io=process("./server.py")
io=remote("host8.dreamhack.games",20738)
available_characters = string.ascii_letters + string.digits + "_-{}"
def read_menu():
    io.recvuntil(b">> ")
def add_flag(file:str):
    read_menu()
    io.sendline(b"4")
    io.sendlineafter(b"Which file to copy >> ", b"flag.txt")
    io.sendlineafter(b"File name >> ", file.encode())
def add_content(file:str, content:str):
    read_menu()
    io.sendline(b"3")
    io.sendlineafter(b"File name >> ", file.encode())
    io.sendlineafter(b"Content >>", content.encode())
def download_file(file:str):
    read_menu()
    io.sendline(b"2")
    io.sendlineafter(b"File name >> ", file.encode())
    io.recvuntil(b"Content :")
    enc = io.recvline().strip()
    return base64.b64decode(enc)
def remove_file(file:str):
    read_menu()
    io.sendline(b"5")
    io.sendlineafter(b"Which file to remove >> ", file.encode())



pt="thisisplaintexthahaitisofcourse"
add_content("test", pt)
enc=download_file("test")
streamkey=[0]*50
comp_pt=zlib.compress(pt.encode())
print(len(enc), len(comp_pt))
for i in range(len(enc)):
    streamkey[i]=enc[i] ^ comp_pt[i]
download_file("flag.txt")
flag_enc=download_file("flag.txt")
flag=[0]*len(flag_enc)
for i in range(len(flag_enc)):
    flag[i]=flag_enc[i] ^ streamkey[i]
flag=zlib.decompress(bytes(flag)).decode()
print(flag)
# no need to length check trick
    
